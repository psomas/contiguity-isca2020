/*
 * Memory defragmentation.
 *
 * Two lists:
 *   1) a mm list, representing virtual address spaces
 *   2) a anon_vma list, representing the physical address space.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/mm_inline.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/hashtable.h>
#include <linux/mem_defrag.h>
#include <linux/shmem_fs.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>
#include <linux/vmstat.h>
#include <linux/migrate.h>
#include <linux/page-isolation.h>
#include <linux/sort.h>

#include <asm/tlb.h>
#include <asm/pgalloc.h>
#include "internal.h"


struct contig_stats {
	int err;
	unsigned long contig_pages;
	unsigned long first_vaddr_in_chunk;
	unsigned long first_paddr_in_chunk;
};

struct defrag_scan_control {
	struct mm_struct *mm;
	unsigned long scan_address;
	char __user *out_buf;
	int buf_len;
	int used_len;
	enum mem_defrag_action action;
	bool scan_in_vma;
	unsigned long vma_scan_threshold;
};


static inline int get_contig_page_size(struct page *page)
{
	int page_size = PAGE_SIZE;

	if (PageCompound(page)) {
		struct page *head_page = compound_head(page);
		int compound_size = PAGE_SIZE<<compound_order(head_page);

		if (head_page != page) {
			VM_BUG_ON_PAGE(!PageTail(page), page);
			page_size = compound_size - (page - head_page) * PAGE_SIZE;
		} else
			page_size = compound_size;
	}

	return page_size;
}
static int do_page_stat(struct mm_struct *mm, struct vm_area_struct *vma,
		struct page *page, unsigned long vaddr,
		char *kernel_buf, int pos, int* remain_buf_len,
		struct contig_stats *contig_stats,
		bool scan_in_vma)
{
	int used_len;
	struct anon_vma *anon_vma;
	int init_remain_len = *remain_buf_len;
	int end_note = -1;
	unsigned long num_pages = page?(get_contig_page_size(page)/PAGE_SIZE):1;

	if (!*remain_buf_len || !kernel_buf)
		return -1;

    //pr_crit("Hello1 !\n");
		long long contig_pages;
		unsigned long paddr = page?PFN_PHYS(page_to_pfn(page)):0;
		bool last_entry = false;

		if (!contig_stats->first_vaddr_in_chunk) {
			contig_stats->first_vaddr_in_chunk = vaddr;
			contig_stats->first_paddr_in_chunk = paddr;
			contig_stats->contig_pages = 0;
		}

		/* scan_in_vma is set to true if buffer runs out while scanning a
		 * vma. A corner case happens, when buffer runs out, then vma changes,
		 * scan_address is reset to vm_start. Then, vma info is printed twice.
		 */
		if (vaddr == vma->vm_start && !scan_in_vma) {
			used_len = scnprintf(kernel_buf + pos, *remain_buf_len, "%p, 0x%lx, "
								 "0x%lx, ",
								 mm,  vma->vm_start, vma->vm_end);

			*remain_buf_len -= used_len;

			if (*remain_buf_len == 1) {
				contig_stats->err = 1;
				goto out_of_buf;
			}
			pos += used_len;
		}

    //pr_crit("Hello2 !\n");
		if (page) {
			if (contig_stats->first_paddr_in_chunk) {
				if (((long long)vaddr - contig_stats->first_vaddr_in_chunk) ==
					((long long)paddr - contig_stats->first_paddr_in_chunk))
					contig_stats->contig_pages += num_pages;
				else {
					/* output present contig chunk */
					contig_pages = contig_stats->contig_pages;
					goto output_contig_info;
				}
			} else { /* the previous chunk is not present pages */
				/* output non-present contig chunk */
				contig_pages = -(long long)contig_stats->contig_pages;
				goto output_contig_info;
			}
		} else {
			/* the previous chunk is not present pages */
			if (!contig_stats->first_paddr_in_chunk) {
				VM_BUG_ON(contig_stats->first_vaddr_in_chunk +
						  contig_stats->contig_pages * PAGE_SIZE !=
						  vaddr);
				++contig_stats->contig_pages;
			} else {
				/* output present contig chunk */
				contig_pages = contig_stats->contig_pages;

				goto output_contig_info;
			}
		}

check_last_entry:
		/* if vaddr is the last page, we need to dump stats as well  */
		if ((vaddr + num_pages * PAGE_SIZE) < vma->vm_end)
			return 0;
		else {
			if (contig_stats->first_paddr_in_chunk)
				contig_pages = contig_stats->contig_pages;
			else
				contig_pages = -(long long)contig_stats->contig_pages;
			last_entry = true;
		}
output_contig_info:
		if (last_entry)
			used_len = scnprintf(kernel_buf + pos, *remain_buf_len, "%lld:0x%llx, -1\n",
								 contig_pages, contig_stats->first_vaddr_in_chunk-contig_stats->first_paddr_in_chunk);
		else
			used_len = scnprintf(kernel_buf + pos, *remain_buf_len, "%lld:0x%llx, ",
								 contig_pages,contig_stats->first_vaddr_in_chunk-contig_stats->first_paddr_in_chunk);
		*remain_buf_len -= used_len;
		if (*remain_buf_len == 1) {
			contig_stats->err = 1;
			goto out_of_buf;
		} else {
			pos += used_len;
			if (last_entry) {
				/* clear contig_stats  */
				contig_stats->first_vaddr_in_chunk = 0;
				contig_stats->first_paddr_in_chunk = 0;
				contig_stats->contig_pages = 0;
				return 0;
			} else {
				/* set new contig_stats  */
				contig_stats->first_vaddr_in_chunk = vaddr;
				contig_stats->first_paddr_in_chunk = paddr;
				contig_stats->contig_pages = num_pages;
				goto check_last_entry;
			}
		}
		return 0;

out_of_buf: /* revert incomplete data  */
	*remain_buf_len = init_remain_len;
	kernel_buf[pos] = '\0';
	return -1;

}

/*
 * Scan single mm_struct.
 * The function will down_read mmap_sem.
 *
 */
static int kmem_defragd_scan_mm(struct defrag_scan_control *sc)
{
	struct mm_struct *mm = sc->mm;
	struct vm_area_struct *vma = NULL;
	unsigned long *scan_address = &sc->scan_address;
	char *stats_buf = NULL;
	int remain_buf_len = sc->buf_len;
	int err = 0;
	struct contig_stats contig_stats;
  unsigned long long total_present_pages=0;
  unsigned long long total_huge_pages=0;

  //pr_crit("Defragd 0\n");
	if (sc->out_buf &&
		sc->buf_len) {
		stats_buf = vzalloc(sc->buf_len);
		if (!stats_buf)
			goto breakouterloop;
	}

  vma = find_vma(mm, *scan_address);
  //pr_crit("Defragd 1\n");
	for (; vma; vma = vma->vm_next) {
		unsigned long vstart, vend;
		struct anchor_page_node *anchor_node = NULL;
		int scanned_chunks = 0;


		vstart = vma->vm_start;
		vend = vma->vm_end;
		if (vstart >= vend)
			goto done_one_vma;
		if (*scan_address > vend)
			goto done_one_vma;
		if (*scan_address < vstart)
			*scan_address = vstart;

		contig_stats = (struct contig_stats) {0};

    //pr_crit("Defragd 2\n");
		while (*scan_address < vend) {
			/*int ret = 1;*/
			struct page *page=NULL;
			/*struct anchor_page_info *anchor_page_info = NULL;*/

			cond_resched();
			down_read(&vma->vm_mm->mmap_sem);
			
      page = follow_page(vma, *scan_address, FOLL_REMOTE);
		
      if(page && !pfn_valid(page_to_pfn(page))) {
        //pr_crit("WHAT THE FUCK? 0x%llx--0x%llx 0x%llx 0x%llx\n", vma->vm_start, vma->vm_end, *scan_address, page_to_pfn(page));
        page=NULL;
        //up_read(&vma->vm_mm->mmap_sem);
        goto _continue;
      } 
      //if(page)
        //pr_crit("Hallelujah!\n");
			

      //pr_crit("Defragd 3\n");

      if(page) {
        total_present_pages+=(get_contig_page_size(page)/PAGE_SIZE);
        if(get_contig_page_size(page) > PAGE_SIZE)
          total_huge_pages+=(get_contig_page_size(page)/PAGE_SIZE);
      }

      //pr_crit("Defragd 4\n");
			if (do_page_stat(mm, vma, page, *scan_address,
						stats_buf, sc->buf_len - remain_buf_len,
						&remain_buf_len, &contig_stats,
						sc->scan_in_vma)) {
				/* reset scan_address to the beginning of the contig.
				 * So next scan will get the whole contig.
				 */
				if (contig_stats.err) {
					*scan_address = contig_stats.first_vaddr_in_chunk;
					sc->scan_in_vma = true;
				}
        up_read(&vma->vm_mm->mmap_sem);
				goto breakouterloop;
			}
      
      //pr_crit("Defragd 5\n");
			/* move to next address */
_continue:

			if (page)
				*scan_address += get_contig_page_size(page);
			else
				*scan_address += PAGE_SIZE;
      
      up_read(&vma->vm_mm->mmap_sem);
		}
done_one_vma:
		sc->scan_in_vma = false;
	}

  ////pr_crit("One: %i\n", sc->buf_len - remain_buf_len);

  if (remain_buf_len && stats_buf && (sc->buf_len - remain_buf_len)) {
				int used_len;
				int pos = sc->buf_len -remain_buf_len;

				used_len = scnprintf(stats_buf + pos, remain_buf_len, "total_present_pages: %llu, -1\n",total_present_pages);
				remain_buf_len -= used_len;
        pos += used_len;
				used_len = scnprintf(stats_buf + pos, remain_buf_len, "total_huge_pages: %llu, -1\n",total_huge_pages);
				remain_buf_len -= used_len;

				if (remain_buf_len == 1) {
					stats_buf[pos] = '\0';
					remain_buf_len = 0;
				}
	}
  ////pr_crit("Two: %i\n", sc->buf_len - remain_buf_len);
breakouterloop:

	if (sc->out_buf &&
		sc->buf_len) {
		err = copy_to_user(sc->out_buf, stats_buf,
				sc->buf_len - remain_buf_len);
		sc->used_len = sc->buf_len - remain_buf_len;
	}

	if (stats_buf)
		vfree(stats_buf);

	/* 0: scan complete, 1: scan_incomplete  */
	return vma == NULL ? 0 : 1;
}

SYSCALL_DEFINE4(scan_process_memory, pid_t, pid, char __user *, out_buf,
				int, buf_len, int, action)
{
	const struct cred *cred = current_cred(), *tcred;
	struct task_struct *task;
	struct mm_struct *mm;
	int err = 0;
	struct defrag_scan_control defrag_scan_control = {0};
	struct mm_slot *iter;


  //pr_crit("Hello %i\n", pid);
	/* Find the mm_struct */
	rcu_read_lock();
	task = pid ? find_task_by_vpid(pid) : current;
	if (!task) {
		rcu_read_unlock();
		return -ESRCH;
	}
	get_task_struct(task);

	/*
	 * Check if this process has the right to modify the specified
	 * process. The right exists if the process has administrative
	 * capabilities, superuser privileges or the same
	 * userid as the target process.
	 */
  //pr_crit("Hello 2 %i\n", pid);
	tcred = __task_cred(task);
	if (!uid_eq(cred->euid, tcred->suid) && !uid_eq(cred->euid, tcred->uid) &&
	    !uid_eq(cred->uid,  tcred->suid) && !uid_eq(cred->uid,  tcred->uid) &&
	    !capable(CAP_SYS_NICE)) {
		rcu_read_unlock();
		err = -EPERM;
		goto out;
	}
	rcu_read_unlock();

	mm = get_task_mm(task);
	put_task_struct(task);

	if (!mm)
		return -EINVAL;

  //pr_crit("Hello 3 %i\n", pid);
	/* reset scan control  */
	if (!defrag_scan_control.mm ||
		defrag_scan_control.mm != mm) {
		defrag_scan_control = (struct defrag_scan_control){0};
		defrag_scan_control.mm = mm;
	}
	defrag_scan_control.out_buf = out_buf;
	defrag_scan_control.buf_len = buf_len;
	defrag_scan_control.action = MEM_DEFRAG_CONTIG_STATS;

	defrag_scan_control.used_len = 0;

	if (unlikely(!access_ok(VERIFY_WRITE, out_buf, buf_len))) {
		err = -EFAULT;
	}
  
  //pr_crit("Hello 4 %i\n", pid);
	/* clear mm once it is fully scanned  */
	if (!kmem_defragd_scan_mm(&defrag_scan_control) &&
		!defrag_scan_control.used_len)
		defrag_scan_control.mm = NULL;

	err = defrag_scan_control.used_len;
  err=0;

  //pr_crit("Bye 1 %i\n", err);
	mmput(mm);
	return err;

out:
  //pr_crit("Bye 2 %i\n", err);
	put_task_struct(task);
	return err;
}





#include"regroup.h"
#include"trace.h"

#define IP_CE             0x8000   /* Flag: "Congestion" */
#define IP_DF             0x4000   /* Flag: "Don't Fragment" */
#define IP_MF            0x2000   /* Flag: "More Fragments" */
#define IP_OFFSET   0x1FFF  /* "Fragment Offset" part */
#define IPF_NEW 1
#define IPF_ISF 0
#define IPF_NOTF -1
#define HASH_SIZE 64
#define IPFRAG_HIGH_THRESH            (256*1024)
#define IPFRAG_LOW_THRESH            (192*1024)
#define IP_FRAG_TIME     (30 * 1000)   /* fragment lifetime */
//hashtable
struct hostfrags **fragtable;
static struct hostfrags *this_host;
static int numpack = 0;





static int timenow;
static u_int32_t time0;
static struct timer_list *timer_head = 0,*timer_tail=0;




/* ******************************************* */
/*            get_whole_ip_packet              */
/* ******************************************* */

void ip_frag_init()
{
	struct timeval tv;
	gettimeofday(&tv,0);
	time0=tv.tv_sec;
	fragtable =(struct hostfrags **)calloc(HASH_SIZE,sizeof(struct hostfrags*));
	if(!fragtable)
	{
		printf("hashtable init failed\n");
		exit(0);
	}
}


int frag_index(struct ndpi_iphdr *iph)
{
	u_int32_t saddr=ntohs(iph->daddr);
	return saddr%HASH_SIZE;
}


int hostfrag_find(struct ndpi_iphdr *iph)
{
	int hash_index = frag_index(iph);
	struct hostfrags *hf;
	this_host = 0;
	for(hf=fragtable[hash_index];hf;hf=hf->next)
	{
		if(hf->ip == iph->daddr)
		{
			this_host=hf;
			break;
		}
	}
	if(!this_host)
		return 0;
	else
		return 1;
}

void hostfrag_create(struct ndpi_iphdr* iph)
{
	struct hostfrags *hf = (struct hostfrags*)malloc(sizeof(struct hostfrags));
	int hash_index = frag_index(iph);
	hf->prev = 0;
	hf->next = fragtable[hash_index];
	if(hf->next)
		hf->next->prev = hf;
	fragtable[hash_index] = hf;
	hf->ip = iph->daddr;
	hf->ipqueue = 0;
	hf->ip_frag_mem = 0;
	hf->hash_index = hash_index;
	this_host = hf;
}


void del_timer(struct timer_list * x)
{
	if (x->prev)
		x->prev->next = x->next;
	else
		timer_head = x->next;
	if (x->next)
		x->next->prev = x->prev;
	else
		timer_tail = x->prev;
}

static void rmthis_host()
{
	int hash_index = this_host->hash_index;
	if (this_host->prev) 
	{
		this_host->prev->next = this_host->next;
		if (this_host->next)
			this_host->next->prev = this_host->prev;
	}
	else 
	{
		fragtable[hash_index] = this_host->next;
		if (this_host->next)
			this_host->next->prev = 0;
	}
	free(this_host);
	this_host = 0;
}

void frag_kfree_skb(struct sk_buff * skb)
{
	if (this_host)
		atomic_sub(skb->truesize, &this_host->ip_frag_mem);
	kfree_skb(skb);
}

void kfree_skb(struct sk_buff * skb)
{
	free(skb);
}


void frag_kfree_s(void *ptr, int len)
{
	if (this_host)
		atomic_sub(len, &this_host->ip_frag_mem);
	free(ptr);
}


void atomic_sub(int ile, int *co)
{
	 *co -= ile;
}

void ip_free(struct ipq * qp)
{

	struct ipfrag *fp;
	struct ipfrag *xp;
	/* Stop the timer for this entry. */
	del_timer(&qp->timer);
	/* Remove this entry from the "incomplete datagrams" queue. */
	if (qp->prev == NULL)
	{
		this_host->ipqueue = qp->next;
		if (this_host->ipqueue != NULL)
			this_host->ipqueue->prev = NULL;
		else
			rmthis_host();
	}
	else
	{
		qp->prev->next = qp->next;
		if (qp->next != NULL)
			qp->next->prev = qp->prev;
	}
	/* Release all fragment data. */
	fp = qp->fragments;
	while (fp != NULL) 
	{
		xp = fp->next;
		frag_kfree_skb(fp->skb);
		frag_kfree_s(fp, sizeof(struct ipfrag));
		fp = xp;
	}
	/* Release the IP header. */
	frag_kfree_s(qp->iph, 64 + 8);
	/* Finally, release the queue descriptor itself. */
	frag_kfree_s(qp, sizeof(struct ipq));
}




void ip_evictor(void)
{
	while (this_host->ip_frag_mem > IPFRAG_LOW_THRESH) 
	{
		if (!this_host->ipqueue)
			ip_free(this_host->ipqueue);
	}
}

struct ipq *ip_find(struct ndpi_iphdr*iph)
{
	struct ipq *qp;
	struct ipq *qplast;
	qplast = NULL;
	for (qp = this_host->ipqueue; qp != NULL; qplast = qp, qp = qp->next) 
	{
		if (iph->id == qp->iph->id &&iph->saddr == qp->iph->saddr &&iph->daddr == qp->iph->daddr &&iph->protocol == qp->iph->protocol)
		{
			del_timer(&qp->timer);
			return (qp);
		}
	}
	return (NULL);
}



int jiffies()
{
	struct timeval tv;
	if (timenow)
		return timenow;
	gettimeofday(&tv, 0);
	timenow = (tv.tv_sec - time0) * 1000 + tv.tv_usec / 1000;
	return timenow;
}



void ip_expire(unsigned long arg)
{
	struct ipq *qp;	   
	qp = (struct ipq *) arg;
	/* Nuke the fragment queue. */
	ip_free(qp);
}




void add_timer(struct timer_list * x)
{
	if (timer_tail) 
	{
		timer_tail->next = x;
		x->prev = timer_tail;
		x->next = 0;
		timer_tail = x;
	}
	else 
	{
		x->prev = 0;
		x->next = 0;
		timer_tail = timer_head = x;
	}
}


void atomic_add(int ile, int *co)
{
	  *co += ile;
}

void *frag_kmalloc(int size)
{
	void *vp = (void *) malloc(size);
	if (!vp)
		return NULL;
	atomic_add(size, &this_host->ip_frag_mem);
	return vp;
}

struct ipq* ip_create(struct ndpi_iphdr *iph)
{
	struct ipq *qp;
	int ihlen;
	qp = (struct ipq *) frag_kmalloc(sizeof(struct ipq));
	if (qp == NULL) 
	{
		//nids_params.no_mem("ip_create");
		return (NULL);
	}
	memset(qp, 0, sizeof(struct ipq));
	/* Allocate memory for the IP header (plus 8 octets for ICMP). */
	ihlen = iph->ihl * 4;
	//64bytes for ipheader 8bytes for icmp
	qp->iph = (struct ndpi_iphdr *)frag_kmalloc(64 + 8);
	if (qp->iph == NULL) 
	{
		//NETDEBUG(printk("IP: create: no memory left !/n"));
		//nids_params.no_mem("ip_create");
		frag_kfree_s(qp, sizeof(struct ipq));
		return (NULL);
	}
	
	memcpy(qp->iph, iph, ihlen + 8);
	qp->len = 0;
	qp->iplen = ihlen;
	qp->fragments = NULL;
	qp->hf = this_host;
	/* Start a timer for this entry. */
	qp->timer.expires = jiffies() + IP_FRAG_TIME;  /* about 30 seconds     */
	qp->timer.data = (unsigned long) qp;  /* pointer to queue     */
	qp->timer.function = ip_expire;     /* expire function      */
	add_timer(&qp->timer);
	qp->prev = NULL;
	qp->next = this_host->ipqueue;
	if (qp->next != NULL)
		qp->next->prev = qp;
	this_host->ipqueue = qp;
	return (qp);
}

struct ipfrag *ip_frag_create(int offset, int end, struct sk_buff * skb, char *ptr)
{
	struct ipfrag *fp;
	fp = (struct ipfrag *) frag_kmalloc(sizeof(struct ipfrag));
	if (fp == NULL) 
	{
		//NETDEBUG(printk("IP: frag_create: no memory left !/n"));
		//nids_params.no_mem("ip_frag_create");
		return (NULL);
	}
	memset(fp, 0, sizeof(struct ipfrag));
	/* Fill in the structure. */
	fp->offset = offset;
	fp->end = end;
	fp->len = end - offset;
	fp->skb = skb;
	fp->ptr = ptr;
	/* Charge for the SKB as well. */
	this_host->ip_frag_mem += skb->truesize;
	return (fp);
}
				                                     
int ip_done(struct ipq * qp)
{
	struct ipfrag *fp;
	int offset;
	//zeq_final_frag
	/* Only possible if we received the final fragment. */
	if (qp->len == 0)
		return (0);
	/* Check all fragment offsets to see if they connect. */
	fp = qp->fragments;
	offset = 0;
	while (fp != NULL) 
	{
		if (fp->offset > offset)
		{
			return (0);         /* fragment(s) missing */
		}
		offset = fp->end;
		fp = fp->next;
	}
	/* All fragments are present. */
	return (1);	
}

char *ip_glue(struct ipq * qp)
{
	char *skb;
	struct ndpi_iphdr *iph;
	struct ipfrag *fp;
	char *ptr;
	int count, len;
	/* Allocate a new buffer for the datagram. */
	len = qp->iplen + qp->len;
	if (len > 65535) 
	{
		//nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_OVERSIZED, qp->iph, 0);
		ip_free(qp);
		return NULL;		
	}
	if ((skb = (char *) malloc(len)) == NULL) 
	{
		//nids_params.no_mem("ip_glue");
		ip_free(qp);
		return (NULL);
	}
	/* Fill in the basic details. */
	ptr = skb;
	memcpy(ptr, ((unsigned char *) qp->iph), qp->iplen);
	ptr += qp->iplen;
	count = 0;
	/* Copy the data portions of all fragments into the new buffer. */
	fp = qp->fragments;
	while (fp != NULL) 
	{
		if (fp->len < 0 || fp->offset + qp->iplen + fp->len > len) {
			//NETDEBUG(printk("Invalid fragment list: Fragment over size./n"));
			//nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_INVLIST, qp->iph, 0);
			ip_free(qp);
			//kfree_skb(skb, FREE_WRITE);
			//ip_statistics.IpReasmFails++;
			free(skb);
			return NULL;
		}
		memcpy((ptr + fp->offset), fp->ptr, fp->len);
		count += fp->len;
		fp = fp->next;
	}
	/* We glued together all fragments, so remove the queue entry. */
	ip_free(qp);
	/* Done with all fragments. Fixup the new IP header. */
	iph = (struct ndpi_iphdr *)skb;
	iph->frag_off = 0;
	iph->tot_len = htons((iph->ihl * 4) + count);
	// skb->ip_hdr = iph;
	//zeq_skb_2
	return (skb);
	
}





char *ip_defrag(struct ndpi_iphdr *iph,struct sk_buff *skb)
{
	struct ipfrag *prev, *next, *tmp;
	struct ipfrag *tfp;
	struct ipq *qp;
	char *skb2;
	char *ptr;
	int flags, offset;
	int i, ihl, end;
	//Trace("find\n");
	if (!hostfrag_find(iph) && skb)
	{
		//Trace("find over\n");
		hostfrag_create(iph);
	}
	//Trace("create over\n");
	if(this_host)
		 if (this_host->ip_frag_mem > IPFRAG_HIGH_THRESH)
			 ip_evictor();
	//Trace("");
	if(this_host)   
		qp = ip_find(iph);
	else
		qp = 0;
	//Trace("");
	offset = ntohs(iph->frag_off); //offset  lower3->frag heigh13->offset 
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	//Trace("");
	if (((flags & IP_MF) == 0) && (offset == 0)) 
	{
		if (qp != NULL)
			ip_free(qp);             /* Fragmented frame replaced by full
										unfragmented copy */
		return 0;
	}
	offset <<= 3;                   /* offset is in 8-byte chunks */
	ihl = iph->ihl * 4;
	//Trace("");
	if(qp!=NULL)
	{
		if (offset == 0) 
		{
		 //更新IP包头信息
			qp->iplen = ihl;
			memcpy(qp->iph, iph, ihl + 8);
		}
		//更新该ipq所对应分片包的失效期限
		del_timer(&qp->timer);
		qp->timer.expires = jiffies() + IP_FRAG_TIME;/* about 30 seconds */
		qp->timer.data = (unsigned long) qp;     /* pointer to queue */
		qp->timer.function = ip_expire; /* expire function */
		add_timer(&qp->timer);	
	}
	else
	{
		/*4.25....................................*/
		if ((qp = ip_create(iph)) == NULL) 
		{
			kfree_skb(skb);
			return NULL;
		}
	}
	 if (ntohs(iph->tot_len) + (int) offset > 65535) 
	 { 
		//nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_OVERSIZED, iph, 0);	
		 kfree_skb(skb);
		 return NULL;
	 }
	 end = offset+ntohs(iph->tot_len)-ihl;

	 
	 ptr = skb->data+ihl;

	 if((flags & IP_MF)==0)
		 qp->len=end;
	 prev = NULL;
	 for(next=qp->fragments;next!=NULL;next=next->next)
	 {
		 if(next->offset>=offset)
			 break;
		 prev=next;
	 }
	if(prev != NULL && offset < prev->end)
	{
		i=prev->end-offset;
		offset+=i;
		ptr+=i;
	}

	for(tmp=next;tmp!=NULL;tmp=tfp)
	{
		tfp=tmp->next;
		if(tmp->offset>=end)
			break;

		i=end-next->offset;
		tmp->len-=i;
		tmp->offset+=i;
		tmp->ptr+=i;
		if(tmp->len<=0)
		{
			if(tmp->prev!=NULL)
			{
				tmp->prev->next=tmp->next;
			}
			else
			{
				qp->fragments = tmp->next;
			}

			if(tmp->next!=NULL)
			{
				tmp->next->prev=tmp->prev;
			}
			next=tfp;
			frag_kfree_skb(tmp->skb);
			frag_kfree_s(tmp,sizeof(struct ipfrag));
		}
	}
	tfp = NULL; 
	tfp = ip_frag_create(offset, end, skb, ptr);
	if (!tfp)
	{
		//nids_params.no_mem("ip_defrag");
		kfree_skb(skb);	
		return NULL;
	}
		//将当前分片加入到prev和tem之间
		/* From now on our buffer is charged to the queues. */
	tfp->prev = prev;
	tfp->next = next;
	if (prev != NULL)
		prev->next = tfp;
	else
		qp->fragments = tfp;
	if (next != NULL)
		next->prev = tfp;
	//该分片所属的IP包是否可重组？
	//Trace("go to IPdone\n");
	if (ip_done(qp))
	{
		//Trace("go to ip_glue()\n");
		skb2 = ip_glue(qp);           /* glue together the fragments */
		//zeq_skb_3
		//继续将重建的ip 包首地址返回给调用函数ip_defrag_stub
		return (skb2);
	}
	//Trace("");
	return NULL;
}



int ip_defrag_stub(struct ndpi_iphdr *iph, struct ndpi_iphdr **defrag)
{
  int offset, flags, tot_len;
  struct sk_buff *skb;
 
  numpack++;
 
//step_1
//分片链表超时处理
  timenow = 0;
  while (timer_head && timer_head->expires < jiffies()) {
    this_host = ((struct ipq *) (timer_head->data))->hf;
    timer_head->function(timer_head->data);
  }
  offset = ntohs(iph->frag_off);
  flags = offset & ~IP_OFFSET;
  offset &= IP_OFFSET;
 
  //step_2
  //是否分片？
  if (((flags & IP_MF) == 0) && (offset == 0)) {
    //step_3
    //在分片链表中查找该IP包的分片数据
    ip_defrag(iph, 0);
    return IPF_NOTF;
  }
  tot_len = ntohs(iph->tot_len);
  skb = (struct sk_buff *) malloc(tot_len + sizeof(struct sk_buff));
  skb->data = (char *) (skb + 1);
  memcpy(skb->data, iph, tot_len);
  skb->truesize = tot_len + sizeof(struct sk_buff);
  //skb->truesize = (skb->truesize + 15) & ~15;
  //skb->truesize += nids_params.sk_buff_size;
 
 
  //zeq_skb_4
  //如果此时ip_defrag返回的指针不为0，即已经重建了ip 包
  //则通过二重指针defrag 将新建IP 包的首地址传递给调用
  //函数gen_ip_frag_proc
  //Trace("go to defrag()\n");
  if((*defrag = (struct ndpi_iphdr *)ip_defrag((struct ndpi_iphdr *) (skb->data),skb)))
    return IPF_NEW;
  else
  {
	//Trace("");
	return IPF_ISF;
  }
}



void ip_frag_exit(void)
{
  if (fragtable) {
    free(fragtable);
    fragtable = NULL;
  }
  /* FIXME: do we need to free anything else? */
}

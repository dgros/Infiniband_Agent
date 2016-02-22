
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>

#include <string.h>

#include <netinet/in.h>
#include <netdb.h>
#include <assert.h>

#include <infiniband/verbs.h>

#define IBPING_TX_DEPTH   20
#define IBPING_RX_DEPTH   2
#define IBPING_RDMA_DEPTH 2
#define IBPING_MAX_SG_SQ  2
#define IBPING_MAX_SG_RQ  2
#define IBPING_MAX_INLINE 128
#define IBPING_WRID_SEND  1
#define IBPING_PORT       1

#define PIGAK_SEQFILE "/proc/pigaseq"
#define PIGAK_REPFILE "/proc/piga_rep"
#define BLOCKSIZE_SEQ 300


#define IBPING_TCP_PORT (8657 + getuid() )

/* Une adresse permettant une connexion IB */
struct ibping_address_s
{
	uint16_t lid;
	uint32_t qpn;
	uint32_t psn;
	uint64_t raddr;
	uint32_t rkey;
};

/** Bloc de variables globales pour l'accès à la carte IB
 */
static struct
{
	/* Info. de base sur la carte IB */
	struct ibv_context*context;   /**< contexte IB (point d'entrée HCA) */
	struct ibv_pd*pd;             /**< Protection Domain */
	struct ibv_mr*mr;             /**< Memory Region correspondant au buffer ci-dessous */
	/* Adresses */
	struct ibping_address_s local_addr; /**< adresse locale */
	struct ibping_address_s peer_addr;  /**< adresse du noeud distant */
	/* Informations de connexion */
	struct ibv_qp*qp;             /**< QP vers le noeud distant */
	struct ibv_cq*of_cq;          /**< CQ pour l'émission */
	struct ibv_cq*if_cq;          /**< CQ pour réception */
	/* boites aux lettres */
	struct
	{
		/* piste de décollage */
		struct
		{
			char data[5536];       /**< données de la boîte à lettres */
			int busy;               /**< flag de présence de données */
		} emission;
		/* piste d'atterrissage */
		struct
		{
			char data[5536];       /**< données de la boîte à lettres */
			volatile int busy;      /**< flag de présence de données */
		} reception;
	} buffer;
} ib_globals;

/* *** Init ************************************************ */

/* Initialise la carte Infiniband (context, PD, MR) */
static void ibping_hca_init(void)
{
	/* find IB device */
//	const size_t SIZE = 1024;
 
//	char *buffer = malloc(SIZE);
	struct ibv_device**dev_list = ibv_get_device_list(NULL);
	if(!dev_list)
	{
		fprintf(stderr, "Infiniband: no device found.\n");
		abort();
	}
	struct ibv_device*ib_dev = dev_list[0];
	fprintf(stderr, "Found IB device '%s'\n", ibv_get_device_name(ib_dev));
	/* open IB context */
	ib_globals.context = ibv_open_device(ib_dev);
	if(ib_globals.context == NULL)
	{
		fprintf(stderr, "Cannot get IB context.\n");
		abort();
	}
	/* allocate Protection Domain */
	ib_globals.pd = ibv_alloc_pd(ib_globals.context);
	if(ib_globals.pd == NULL)
	{
		fprintf(stderr, "Cannot allocate IB protection domain.\n");
		abort();
	}
	/* register Memory Region */
	printf("%p \n",ib_globals.pd );  
//	ib_globals.mr = ibv_reg_mr(ib_globals.pd,buffer,
//			sizeof(buffer),
			//IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE);
//			IBV_ACCESS_LOCAL_WRITE);

	ib_globals.mr = ibv_reg_mr(ib_globals.pd, &ib_globals.buffer,
			sizeof ib_globals.buffer,
			IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE);
		//	IBV_ACCESS_LOCAL_WRITE);*/
	if(ib_globals.mr == NULL)
	{
		fprintf(stderr, "Couldn't register MR\n");
		abort();
	}
}

static void ibping_connection_init(void)
{
	/* init outgoing CQ */
	ib_globals.of_cq = ibv_create_cq(ib_globals.context, IBPING_TX_DEPTH, NULL, NULL, 0);
	if(ib_globals.of_cq == NULL)
	{
		fprintf(stderr, "Couldn't create out CQ\n");
		abort();
	}
	/* init incoming CQ */
	ib_globals.if_cq = ibv_create_cq(ib_globals.context, IBPING_RX_DEPTH, NULL, NULL, 0);
	if(ib_globals.if_cq == NULL)
	{
		fprintf(stderr, "Couldn't create in CQ\n");
		abort();
	}
	/* create QP */
	struct ibv_qp_init_attr qp_init_attr =
	{
		.send_cq = ib_globals.of_cq,
		.recv_cq = ib_globals.if_cq,
		.cap     = {
			.max_send_wr     = IBPING_TX_DEPTH,
			.max_recv_wr     = IBPING_RX_DEPTH,
			.max_send_sge    = IBPING_MAX_SG_SQ,
			.max_recv_sge    = IBPING_MAX_SG_RQ,
			.max_inline_data = IBPING_MAX_INLINE
		},
		.qp_type = IBV_QPT_RC
	};
	ib_globals.qp = ibv_create_qp(ib_globals.pd, &qp_init_attr);
	if(ib_globals.qp == NULL)
	{
		fprintf(stderr, "Couldn't create QP\n");
		abort();
	}
	/* init QP- step: INIT */
	struct ibv_qp_attr qp_attr =
	{
		.qp_state        = IBV_QPS_INIT,
		.pkey_index      = 0,
		.port_num        = IBPING_PORT,
		.qp_access_flags = IBV_ACCESS_REMOTE_WRITE
	};
	int rc = ibv_modify_qp(ib_globals.qp, &qp_attr,
			IBV_QP_STATE              |
			IBV_QP_PKEY_INDEX         |
			IBV_QP_PORT               |
			IBV_QP_ACCESS_FLAGS);
	if(rc != 0)
	{
		fprintf(stderr, "Failed to modify QP to INIT\n");
		abort();
	}
	/* init local address */
	struct ibv_port_attr port_attr;
	rc = ibv_query_port(ib_globals.context, IBPING_PORT, &port_attr);
	if(rc != 0)
	{
		fprintf(stderr, "Couldn't get local LID.\n");
		abort();
	}
	fprintf(stderr, "local LID  = 0x%02X\n", port_attr.lid);
	ib_globals.local_addr = (struct ibping_address_s)
	{
		.lid   = port_attr.lid,
			.qpn   = ib_globals.qp->qp_num,
			.psn   = lrand48() & 0xffffff,
			.raddr = (uintptr_t)&ib_globals.buffer,
			.rkey  = ib_globals.mr->rkey
	};
}


static void ibping_connection_connect(struct ibping_address_s*dest)
{
	/* connect QP- step: RTR */
	struct ibv_qp_attr attr = {
		.qp_state		= IBV_QPS_RTR,
		.path_mtu		= IBV_MTU_1024,
		.dest_qp_num	= dest->qpn,
		.rq_psn 		= dest->psn,
		.max_dest_rd_atomic	= IBPING_RDMA_DEPTH,
		.min_rnr_timer	= 12, /* 12 */
		.ah_attr		= {
			.is_global	= 0,
			.dlid		= dest->lid,
			.sl		= 0,
			.src_path_bits	= 0,
			.port_num	        = IBPING_PORT
		}
	};
	int rc = ibv_modify_qp(ib_globals.qp, &attr,
			IBV_QP_STATE              |
			IBV_QP_AV                 |
			IBV_QP_PATH_MTU           |
			IBV_QP_DEST_QPN           |
			IBV_QP_RQ_PSN             |
			IBV_QP_MAX_DEST_RD_ATOMIC |
			IBV_QP_MIN_RNR_TIMER);
	if(rc != 0)
	{
		fprintf(stderr, "Failed to modify QP to RTR\n");
		abort();
	}
	/* connect QP- step: RTS */
	attr.qp_state      = IBV_QPS_RTS;
	attr.timeout 	     = 14; /* 14 */
	attr.retry_cnt     = 7;  /* 7 */
	attr.rnr_retry     = 7;  /* 7 = infinity */
	attr.sq_psn 	     = ib_globals.local_addr.psn;
	attr.max_rd_atomic = IBPING_RDMA_DEPTH; /* 1 */
	rc = ibv_modify_qp(ib_globals.qp, &attr,
			IBV_QP_STATE              |
			IBV_QP_TIMEOUT            |
			IBV_QP_RETRY_CNT          |
			IBV_QP_RNR_RETRY          |
			IBV_QP_SQ_PSN             |
			IBV_QP_MAX_QP_RD_ATOMIC);
	if(rc != 0)
	{
		fprintf(stderr,"Failed to modify QP to RTS\n");
		abort();
	}

}

/* ** Echange d'adresses *********************************** */

/* echange des adresses via une connexion de bottstrap en TCP/IP */
static void ibping_address_exchange(const char*peer)
{
	int s = socket(AF_INET, SOCK_STREAM, 0);
	assert(s);
	if(peer)
	{
		/* client */
		struct hostent* he = gethostbyname(peer);
		assert(he);
		struct sockaddr_in inaddr;
		struct in_addr*ip = (struct in_addr*)he->h_addr;
		inaddr.sin_family = AF_INET;
		inaddr.sin_port = htons(IBPING_TCP_PORT);
		inaddr.sin_addr = *ip;
		int rc = connect(s, (struct sockaddr*)&inaddr, sizeof(struct sockaddr_in));
		if(rc)
		{
			fprintf(stderr, "Cannot connect to %s:%d\n", peer, IBPING_TCP_PORT);
			abort();
		}
		rc = recv(s, &ib_globals.peer_addr, sizeof(struct ibping_address_s), MSG_WAITALL);
		assert(rc == sizeof(struct ibping_address_s));
		rc = send(s, &ib_globals.local_addr, sizeof(struct ibping_address_s), 0);
		assert(rc == sizeof(struct ibping_address_s));
		close(s);
	}
	else
	{
		/* server */
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(IBPING_TCP_PORT);
		addr.sin_addr.s_addr = INADDR_ANY;
		int rc = bind(s, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
		if(rc)
		{
			fprintf(stderr, "Bind error (%s)\n", strerror(errno));
			abort();
		}
		listen(s, 10);
		unsigned int addr_size = sizeof(struct sockaddr_in);
		int p = accept(s, (struct sockaddr*)&addr, &addr_size);
		assert(p != -1);
		rc = send(p, &ib_globals.local_addr, sizeof(struct ibping_address_s), 0);
		assert(rc == sizeof(struct ibping_address_s));
		rc = recv(p, &ib_globals.peer_addr, sizeof(struct ibping_address_s), MSG_WAITALL);
		assert(rc == sizeof(struct ibping_address_s));
		close(s);
	}
}

/* ** RDMA ************************************************* */

/* Lance un envoi RDMA.
 * 'buf'    : pointeur sur les données à envoyer
 * 'size'   : tailles des données à envoyer
 * '_raddr' : adresse mémoire de réception (dans l'espace d'adressage du récepteur)
 * Note : fonction non-bloquante.
 */
static void ibping_rdma_send(const void*buf, int size, uintptr_t _raddr)
{
	const uint64_t raddr = (uint64_t)_raddr;
	struct ibv_sge list = {
		.addr   = (uintptr_t)buf,
		.length = size,
		.lkey   = ib_globals.mr->lkey
	};
	struct ibv_send_wr wr = {
		.wr_id      = IBPING_WRID_SEND,
		.sg_list    = &list,
		.num_sge    = 1,
		.opcode     = IBV_WR_RDMA_WRITE,
		.send_flags = IBV_SEND_SIGNALED,
		.wr.rdma =
		{
			.remote_addr = raddr,
			.rkey        = ib_globals.peer_addr.rkey
		}
	};
	struct ibv_send_wr*bad_wr = NULL;
	int rc = ibv_post_send(ib_globals.qp, &wr, &bad_wr);
	if(rc)
	{
		fprintf(stderr, "post RDMA send failed.\n");
		abort();
	}
}

/* Attend la fin de tous les les envois RDMA en cours.
 */
static void ibping_rdma_wait(void)
{
	struct ibv_wc wc;
	int ne = 0;
	do
	{
		ne = ibv_poll_cq(ib_globals.of_cq, 1, &wc);
		if(ne < 0)
		{
			fprintf(stderr, "poll out CQ failed.\n");
			abort();
		}
	}
	while(ne == 0);
	if(ne != 1 || wc.status != IBV_WC_SUCCESS)
	{
		fprintf(stderr, "WC send failed (status=%d)\n", wc.status);
		abort();
	}
}

/* ********************************************************* */

FILE *piga_seq_file, *piga_rep_file;



char  * hostname = NULL;
char * file_write =NULL;
char * file_read =NULL;


int main(int argc, char**argv)
{
	srand48(getpid() * time(NULL));
	if(argc != 1 && argc != 2)
	{
		exit(1);
	}
	ib_globals.buffer.reception.busy = 0;
	ibping_hca_init();
	ibping_connection_init();
	ibping_address_exchange(argv[1]);
	ibping_connection_connect(&ib_globals.peer_addr);
	fprintf(stderr, "remote LID = 0x%02X\n", ib_globals.peer_addr.lid);

	int size;// = strlen(message) + 1;
	FILE * file = NULL;

	if(argc == 1)
	{
		piga_seq_file=fopen(PIGAK_SEQFILE,"r");
		if (piga_seq_file == NULL) {
			perror("Error opening seq_file (read only)");
			exit(0);
		}
		piga_rep_file=fopen(PIGAK_REPFILE,"w");
		if (piga_rep_file == NULL) {
			perror("Error opening rep_file (write only)");
			exit(0);
		}

		 ssize_t read;
                size_t len;
                char *line= NULL;
		line = (char *)malloc(len +1);
		printf("je suis l'emetteur %i\n", (int)getpid());
		while( (read=getline(&line, &len, piga_seq_file)) != -1 )
		{
			size = strlen(line);
			printf("%s", line);
			memcpy(ib_globals.buffer.emission.data, line, size);
			const char*const base = (char*)&ib_globals.buffer;
			ibping_rdma_send(&ib_globals.buffer.emission.data[0], size,
					(&ib_globals.buffer.reception.data[0] - base) + ib_globals.peer_addr.raddr);
			ibping_rdma_wait();
			ib_globals.buffer.emission.busy = 1;
			ibping_rdma_send(&ib_globals.buffer.emission.busy, sizeof(int),
					((char*)&ib_globals.buffer.reception.busy - base) + ib_globals.peer_addr.raddr);
			ibping_rdma_wait();
			
			bzero(ib_globals.buffer.reception.data, sizeof(ib_globals.buffer.reception.data));
                        while(!ib_globals.buffer.reception.busy)
                        {
                        }
			printf("%s", ib_globals.buffer.reception.data);
			fwrite(ib_globals.buffer.reception.data, 1, strlen(ib_globals.buffer.reception.data), piga_rep_file);
		        fflush(piga_rep_file);  
                        ib_globals.buffer.reception.busy = 0;
		}
		if(piga_seq_file != NULL) fclose(piga_seq_file);
		if(piga_rep_file != NULL) fclose(piga_rep_file);
	}

	if(file != NULL) fclose(file);
	return 0;
}


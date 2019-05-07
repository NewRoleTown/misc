#define _GNU_SOURCE
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/epoll.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<assert.h>
#include<string.h>
#include<errno.h>
#include<netdb.h>
#include<assert.h>
#include<sys/types.h>
#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>
#include<sched.h>
#include<pthread.h>
#include<sys/mman.h>
#include<sys/ipc.h>
#include<sys/shm.h>
#include<signal.h>

#include<stdio.h>
#include<zlog.h>

#include"mqtt.h"
#include"db.h"
#include"common.h"
#include"http.h"

#include"cJSON.h"


#define MAX_CONNECTION_NUM	8192
#define BUFFER_DEFAULT_SIZE	1024

#define log_print	printf

#define atomic_incl(x) asm volatile("lock incl %0"::"m"(x):)
#define atomic_decl(x) asm volatile("lock decl %0"::"m"(x):)

#define SHM_PATH	"./shm_lock"
pthread_mutex_t *mutex;
pthread_mutexattr_t mutexAttr;


int epoll_fd = -1;
int listen_fd = -1;
int timeout = 500;
int holdlock = 0;
int g_cid = -1;
MYSQL *sqlConn;
zlog_category_t *zc;

#define MAX_EPOLL_WAIT_NUM	128
struct epoll_event *pevent_ret = NULL;

union epoll_data listen_fd_epoll_data;

struct epoll_event listen_fd_epoll_event;

int SetNonBlock(int iSock){
	int iFlags = fcntl(iSock,F_GETFL,0);
	iFlags |= O_NONBLOCK;
	iFlags |= O_NDELAY;
	return fcntl(iSock, F_SETFL, iFlags);
}

int set_affinity( long idx ){
	long ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	if( idx >= ncpus )
		return -1;

	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(idx, &mask); 
	if (sched_setaffinity(0, sizeof(mask), &mask) < 0) {
		zlog_info(zc,"sched_setaffinity\n");
		return -1;
	}

	return 0;
}

struct listening{
	void *data;
	int listen_fd;
	struct sockaddr_in sa;
	socklen_t socklen;
	int backlog;

	struct connection *conn;
};
struct listening g_listening;

struct event{
	void *data;
	struct connection *conn;
	void (*handler)(struct event *);
};

struct connection{
	int fd;
	void *data;
	struct event *read_event;
	struct event *write_event;
	struct listening *listen;
	struct sockaddr_in sa;

	unsigned int ref;

	char *buffer;
	unsigned int buffer_size;
	unsigned int buffer_pos;
	unsigned int buffer_start;

	unsigned int info1;
	unsigned int info2;
	unsigned int stat;
	void *ctx;
};


#define NEXTARR_MAX_LEN		0x100
#define RETURN_MALLOC	
RETURN_MALLOC int *calc_next( char *pattern,int len ){
	if( len > NEXTARR_MAX_LEN ){
		return NULL;
	}

	int *next = malloc( sizeof(int) * len );

	if( !next ){
		return NULL;
	}

	int begin = 1;
	int matched = 0;
	next[0] = 0;

	while( begin + matched < len ){
		if( pattern[begin + matched] == pattern[matched] ){
			next[begin + matched] = matched + 1;
			matched++;
		}else if( !matched ){
			begin++;
		}else{
			begin += (matched - next[matched - 1]);
			matched = next[matched - 1];
		}
	}

	return next;
}


int search_pattern( char *text,int text_len,char *pattern,int pattern_len,int *next ){
	if( !next ){
		next = calc_next( pattern,pattern_len );
		if( !next )
			return -1;
	}

	int matched = 0;
	int begin = 0;

	while( begin + matched < text_len ){
		if( text[begin + matched] == pattern[matched] ){
			matched++;
			if( matched == pattern_len )
				return begin;
		}else if( !matched ){
			begin++;
		}else{
			begin += (matched - next[matched - 1])	;
			matched = next[matched - 1];
		}
	}

	return -2;
}

#define PRINT_DIRECT
#ifdef PRINT_DIRECT
#define zlog_info(c,fmt,args...) 	printf(fmt"\n",##args)
#define zlog_error(c,fmt,args...) 	printf(fmt"\n",##args)
#define zlog_debug(c,fmt,args...) 	printf(fmt"\n",##args)
#endif


char ClientID[24];
char UserName[64];
char PassWord[64];

#define MQTT_HEAD_NOT_FULL		0x1
#define MQTT_CTX_NOT_FULL		0x2


void analysis_mqtt_publish_payload( const char *text,int len ){
}

RETURN_MALLOC int *get_subscriber( char *str,int *pargc ){
	char sql[128];
	/*
	char pub_name[64];
	
	memcpy( pub_name,str->pstr,str->len );
	pub_name[str->len] = '\0';
	*/
	sprintf( sql,"select fd from Subscribe where path='%s';",str);

	zlog_debug(zc,"##############%s###############\n",sql);
	return get_int_from_db( sqlConn,sql,pargc );
}

int analysis_mqtt( struct connection *pconn ){
	struct mqtt_fixed_header *pfixed_header = (struct mqtt_fixed_header *)&(pconn->buffer[pconn->buffer_start]);

	int msgSize = pconn->buffer_pos - pconn->buffer_start;

	int remainSize = 0;
	unsigned char *ps = pfixed_header->size;
	int i = 0;
	int si = 0;

	log_print("----------------------------------------------------\n");
	if( pconn->stat == MQTT_FIX_HEAD_NONE ){

		if( msgSize < sizeof(struct mqtt_fixed_header) ){
			assert( pconn->stat == MQTT_FIX_HEAD_NONE );
			return MQTT_HEAD_NOT_FULL;
		}


		while( (*(ps + i)) & 0x80 ){
			i++;
			if( sizeof(struct mqtt_fixed_header) + i > msgSize )
				return MQTT_HEAD_NOT_FULL;
			if( i > 3 ){
				return -MQTT_LENGTH_ERROR;
			}
		}

		si = i;

		while( i >= 0  ){
			remainSize = (remainSize << 7) + ((*(ps + i)) & 0x7f);
			i--;
		}

		pconn->info1 = remainSize;
		pconn->info2 = si;
		pconn->stat = MQTT_FIX_HEAD_READDONE;

		if( msgSize < (remainSize + sizeof(struct mqtt_fixed_header) + i) ){
			return MQTT_CTX_NOT_FULL;
		}
	}

	assert( pconn->stat == MQTT_FIX_HEAD_READDONE );
	remainSize = pconn->info1;
	si = pconn->info2;


	//	log_print("-------------REMAIN = %d\n",remainSize);

	struct mqtt_variable_header *pvariable_header = (struct mqtt_variable_header *)(&(pconn->buffer[pconn->buffer_start + sizeof(struct mqtt_fixed_header) + si]));
	char name_buffer[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	unsigned char pingresp[2] = {0xd0,0x00};
	char buffer[64];
	unsigned short msgId;
	int argc;
	char sql[256];

	char *pt = NULL;
	unsigned short var_len;
	struct mqtt_ver_flag_hb *pver_flag_hb;
	int tR;
	int trS;
	struct serv_str *p;

	log_print("PACK TYPE = %d QOS = %d\n",pfixed_header->type,pfixed_header->qosLv);
	switch( pfixed_header->type ){
	case MQTT_TYPE_CONN:

		//log_print("msb = %d\t\tlsb = %d\n",pvariable_header->msb,pvariable_header->lsb);
		memcpy( name_buffer, &(pvariable_header->name[pvariable_header->msb]), pvariable_header->lsb - pvariable_header->msb );
		log_print("REQUEST NAME:\t\t%s\n",name_buffer);

		pver_flag_hb = (struct mqtt_ver_flag_hb *)(&pvariable_header->name[pvariable_header->lsb]);
		log_print("HEART BEAT:\t\t%d\n",ntohs(pver_flag_hb->heart_beat) );

		pt = (char *)pver_flag_hb + sizeof(struct mqtt_ver_flag_hb);

		//if( (1 == pfixed_header->qosLv) || (2 == pfixed_header->qosLv) ){

		var_len = ntohs(*(unsigned short *)pt);
		if( var_len >= 24 ){

		}

		memset(ClientID,0,sizeof(ClientID));
		memset(UserName,0,sizeof(UserName));
		memset(PassWord,0,sizeof(PassWord));

		pt += sizeof(unsigned short);

		memcpy( ClientID, pt, var_len );
		log_print("CLIENT ID:\t\t%s\n",ClientID);

		pt += var_len;
		//}

		if( pver_flag_hb->will_flag ){
			//topic
			var_len = ntohs(*(unsigned short *)pt);
			pt += sizeof(unsigned short);
			pt += var_len;

			//message
			var_len = ntohs(*(unsigned short *)pt);
			pt += sizeof(unsigned short);
			pt += var_len;
		}

		if( pver_flag_hb->usr_flag ){
			var_len = ntohs(*(unsigned short *)pt);
			pt += sizeof(unsigned short);

			memcpy( UserName, pt, var_len );
			log_print("USERNAME:\t\t%s\n",UserName);
			pt += var_len;
		}

		if( pver_flag_hb->pwd_flag ){
			var_len = ntohs(*(unsigned short *)pt);
			pt += sizeof(unsigned short);

			memcpy( PassWord, pt, var_len );
			log_print("PASSWORD:\t\t%s\n",PassWord);
			pt += var_len;
		}


		memset(sql,0,sizeof(sql));
		sprintf( sql,"select fd from LoginUser where sn='%s'",ClientID );
		int dup_num;
		int *arr = get_int_from_db(sqlConn,sql,&dup_num);

		memset(sql,0,sizeof(sql));
		if( !arr ){
			sprintf( sql,"insert into LoginUser values('%s','%s',%d,%d);",ClientID,inet_ntoa(pconn->sa.sin_addr),g_cid,pconn->fd);
			exec_sql_str( sqlConn, sql );
		}else{
			zlog_error(zc,"dup sn");
			if( dup_num > 1 ){
				zlog_error(zc,"dup double sn");
				assert(0);
			}
			if( arr[0] == pconn->fd ){
				zlog_error(zc,"reuse fd");
			}else{
				epoll_ctl( epoll_fd, EPOLL_CTL_DEL,arr[0],NULL );
				close(arr[0]);
			}
			sprintf( sql,"update LoginUser set ip='%s',cid=%d,fd=%d where sn='%s'",
					inet_ntoa(pconn->sa.sin_addr),g_cid,pconn->fd,ClientID );
			exec_sql_str( sqlConn, sql );
			memset(sql,0,sizeof(sql));

			sprintf( sql,"delete from Subscribe where sn='%s'",ClientID );
			exec_sql_str( sqlConn, sql );



			free(arr);
		}

		//ok response
		log_print("start send connack\n");

		struct mqtt_serv_response response;

		response.type = MQTT_TYPE_CONNACK;
		response.len = 2;
		response.res = 0;
		response.ret = 0;


		send( pconn->fd,&response,sizeof(response),0 );

		break;

	case MQTT_TYPE_PUBLISH:

		tR = remainSize;

		tR = remainSize;
		pt = (char *)pfixed_header + sizeof(struct mqtt_fixed_header) + si;

		var_len = ntohs(*(unsigned short *)pt);

		pt += sizeof(unsigned short);
		tR -= sizeof(unsigned short);

		memcpy( buffer,pt,var_len );
		buffer[var_len] = '\0';


		pt += var_len;
		tR -= var_len;

		log_print("PUBLISH %s\n",buffer);

		if( pfixed_header->qosLv ){
			msgId = ntohs(*(unsigned short *)pt);
			pt += sizeof(unsigned short);
			tR -= sizeof(unsigned short);
		}

		if( pfixed_header->qosLv == 1 ){
			char *puback_response = (char *)malloc(2 + 2);	//ABAB

			puback_response[0] = 0x40;
			puback_response[1] = 0x02;
			puback_response[2] = 0x00;
			puback_response[3] = msgId;

			send( pconn->fd,puback_response,2 + (pfixed_header->qosLv?2:0),0 );

			free(puback_response);	//CDCD
		}

		char buffer_tmp[512];
		memcpy( buffer_tmp,pt,sizeof(buffer_tmp));
		buffer_tmp[511] = '\0';
		buffer_tmp[tR] = '\0';
		log_print("payload = %s\n",buffer_tmp);

		p = split_string( buffer,var_len,'/',&argc );	//ABAB

		int nSub;
		int *arr_sub = get_subscriber( buffer,&nSub );	//ABAB
		zlog_debug( zc,"return %d messages\n",nSub );

		int ret;
		if( arr_sub ){
			int h;
			for( h = 0; h < nSub; h++ ){
				ret = send( arr_sub[h],pconn->buffer + pconn->buffer_start,
						remainSize + si + sizeof(struct mqtt_fixed_header), 0);
				log_print("<<SEND>> %d\n",ret);
			}
			free(arr_sub);	//CDCD
		}

		if( !strncmp(p[argc-1].pstr,"data",4) ){
			cJSON *pJson = cJSON_Parse( pt );

			if( !pJson ){

			}else{
				cJSON *latObj = cJSON_GetObjectItem( pJson,"1792" );
				if( !latObj )
					latObj = cJSON_GetObjectItem( pJson,"1480" );
				char *lat = (latObj?latObj->valuestring:"");

				cJSON *lonObj = cJSON_GetObjectItem( pJson,"087B" );
				if( !lonObj )
					lonObj = cJSON_GetObjectItem( pJson,"00EA" );

				char *lon = (lonObj?lonObj->valuestring:"");

				cJSON *timeObj = cJSON_GetObjectItem( pJson,"18F3" );
				char *time = (timeObj?timeObj->valuestring:"");

				//char *power = cJSON_GetObjectItem( pJson,"1E9D" )->valuestring;

				memcpy( buffer_tmp,p[argc-2].pstr,p[argc-2].len );
				buffer_tmp[p[argc-2].len] = '\0';

				double tsRet[2] = {0.0,0.0};

				double lat_d,lon_d;

				sscanf(lat,"%lf",&lat_d);
				sscanf(lon,"%lf",&lon_d);

				/*
				if( lat && lon )
					Transform( lat_d, lon_d, tsRet );
				*/

				memset(sql,0,sizeof(sql));
				//sprintf( sql,"insert into T values('%s',%s,'%.6lf','%.6lf','%s');",buffer_tmp,"0",tsRet[0],tsRet[1],(time?time:""));
				sprintf( sql,"insert into T values('%s',%s,'%.6lf','%.6lf','%s');",buffer_tmp,"0",lat_d,lon_d,(time?time:""));
				printf("----------%s---------\n",sql);
				exec_sql_str( sqlConn,sql );
				
				cJSON_Delete(pJson);
			}


		}

		if(p)
			free(p);	//CDCD


		break;

	case MQTT_TYPE_SUBSCRIBE:

		if( 0x82 != *(unsigned char *)pfixed_header){

		}

		pt = (char *)pfixed_header + sizeof(struct mqtt_subscribe_header) + si;

		msgId = ntohs(*(unsigned short *)pt);
		zlog_debug(zc,"SUBSCRIBE ID = %d\n",msgId);
		pt += sizeof(unsigned short);

		trS = remainSize;
		trS -= sizeof(unsigned short);
		i = 0;
		while( trS ){
			zlog_debug(zc,"SUBSCRIBE msg id = %d\n",i);
			i++;
			var_len = ntohs(*(unsigned short *)pt);

			pt += sizeof(unsigned short);
			memcpy( buffer,pt,var_len );		
			buffer[var_len] = '\0';
			zlog_debug(zc,"SUBSCRIBE PATH = %d,%s\n",var_len,buffer);

			memset( sql,0,sizeof(sql) );
			sprintf( sql,"insert into Subscribe values('%s','%s',%d,%d);",ClientID,buffer,g_cid,pconn->fd );
			exec_sql_str( sqlConn,sql );

			pt += var_len;

			if( *(unsigned char *)pt > 0x2 ){

			}

			pt += 1;
			trS -= (var_len + sizeof(unsigned short) + 1);

		}

		zlog_debug(zc,"OUT SUBSCRIBE LOOP+++++++++++++++++++++++\n");

		unsigned char *suback_response = (unsigned char *)malloc( 2 + 2 + i );

		suback_response[0] = 0x90;
		suback_response[1] = 2 + i;
		suback_response[2] = 0x00;
		suback_response[3] = (unsigned char)msgId;
		suback_response[4] = 0x1;

		send( pconn->fd,suback_response,2 + 2 + i,0 );


		free( suback_response );
		break;
	case MQTT_TYPE_UNSUB:

		zlog_debug(zc,"MQTT_TYPE_UNSUB\n");

		if( *(unsigned char *)pfixed_header != 0xa2 ){
			zlog_error(zc,"$$$$$$$$$$$$$$MQTT_TYPE_UNSUB$$$$$$$$$$$$$$\n");
		}

		pt = (char *)pfixed_header + sizeof(struct mqtt_subscribe_header) + si;

		msgId = ntohs(*(unsigned short *)pt);
		pt += sizeof(unsigned short);

		trS = remainSize;
		trS -= sizeof(unsigned short);
		i = 0;
		while( trS ){
			zlog_debug(zc,"UNSUBSCRIBE msg id = %d\n",i);
			i++;
			var_len = ntohs(*(unsigned short *)pt);

			pt += sizeof(unsigned short);
			memcpy( buffer,pt,var_len );		
			buffer[var_len] = '\0';
			zlog_debug(zc,"UNSUBSCRIBE PATH = %d,%s\n",var_len,buffer);

			//memset( sql,0,sizeof(sql) );
			//sprintf( sql,"insert into Subscribe values('%s','%s',%d,%d);",ClientID,buffer,g_cid,pconn->fd );
			//exec_sql_str( sqlConn,sql );

			pt += var_len;

			trS -= (var_len + sizeof(unsigned short));
		}

		zlog_debug(zc,"OUT UNSUBSCRIBE LOOP+++++++++++++++++++++++\n");

		unsigned char *unsuback_response = (unsigned char *)malloc(4 );	//ABAB

		if( !unsuback_response ){
			assert(0);
		}

		suback_response[0] = 0xb2;
		suback_response[1] = 2;
		suback_response[2] = 0x00;
		suback_response[3] = (unsigned char)msgId;

		send( pconn->fd,unsuback_response,4,0 );


		free( suback_response );	//CDCD

		break;
	case MQTT_TYPE_PINGREQ:

		zlog_debug(zc,"MQTT_TYPE_PINGREG\n");
		send( pconn->fd,pingresp,sizeof(pingresp),0 );

		break;
	case MQTT_TYPE_DISCONNECT:
		epoll_ctl( epoll_fd, EPOLL_CTL_DEL,pconn->fd,NULL );
		close( pconn->fd );
		log_print("close pconn %s:%d\n",inet_ntoa(pconn->sa.sin_addr),ntohs(pconn->sa.sin_port));

		/*
		memset( sql,0,sizeof(sql) );
		sprintf( sql,"delete from Subscribe where sn='%s'",ClientID );
		exec_sql_str( sqlConn, sql );
		*/
		break;
	default:
		epoll_ctl( epoll_fd, EPOLL_CTL_DEL,pconn->fd,NULL );
		close( pconn->fd );
		zlog_error("close pconn can't parse request code%s:%d\n",inet_ntoa(pconn->sa.sin_addr),ntohs(pconn->sa.sin_port));
		break;
	}


	pconn->buffer_start += (remainSize + si + sizeof(struct mqtt_fixed_header));

	pconn->stat = MQTT_FIX_HEAD_NONE;


	log_print("\n\n");
	if( pconn->buffer_start == pconn->buffer_pos ){
		pconn->buffer_start = pconn->buffer_pos = 0;
		//log_print("remain = %d\t\tsize = %d\t\tpos = %d\n",remainSize,remainSize+sizeof(struct mqtt_fixed_header) + si,pconn->buffer_pos);
	}else{
		log_print("remain = %d\t\tsize = %d\t\tpos = %d\n",remainSize,remainSize+sizeof(struct mqtt_fixed_header) + si,pconn->buffer_pos);
		analysis_mqtt( pconn );
	}


	return 0;

}

#define HTTP_HEAD_NONE			0x0
#define HTTP_HEAD_NOT_FULL 		0x1
#define HTTP_HEAD_FULL			0x2

int edl_next[] = {-1,0,1,2};

int handle_http_head( struct connection *pconn,char *text,int len ){
	struct http_head_format *p = parse_http_head( text,len );
	if( !p )
		return -1;

	print_http_format( p );

	char filename[32];
	memcpy( filename,p->url.pstr + 1,p->url.len - 1 );
	filename[p->url.len - 1] = '\0';

	int fd = open(filename,O_RDONLY);
	if( fd == -1 ){
		zlog_error(zc,"file open error");
		char buff[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 17\r\bConnection: keep-alive\r\n\r\nNo Page Avaliable";
		zlog_error(zc,"404 not found %s\n",filename);
		send( pconn->fd,buff,strlen(buff),0 );
		free(p);
	}else{
		struct http_pack hp;
		memset( &hp,0,sizeof(hp) );

		hp.size = 4096;
		hp.buff = (char *)malloc(4096);
		memset( hp.buff,0,4096);

		http_addline( &hp,HTTP_OK_STR,strlen(HTTP_OK_STR) );
		http_addline( &hp,"Content-Type: text/html",23);
		http_addline( &hp,"Server: nginx/1.0.14",20);
		http_addline( &hp,"Connection: keep-alive",22);

		char buffer[256];
		int x = read(fd,buffer,256);
		char buff[128];
		memset(buff,0,sizeof(buff));
		sprintf(buff,"Content-Length: %d",x);

		http_addline(&hp,buff,strlen(buff));
		http_endline(&hp);
		http_addline(&hp,buffer,x);
		//http_endline(&hp);
		//log_print("%s\n",hp.buff);
		send( pconn->fd,hp.buff,hp.pos,0 );
		close(fd);
		free(p);
	}


	/*
	if( !strncmp(p->url.pstr,"/index.html",p->url.len) ){
		int fd = open("tp.htmc",O_RDONLY);
		if( fd == -1 ){
			log_print("file open error\n");
			return -2;
		}
		struct http_pack hp;
		memset( &hp,0,sizeof(hp) );

		hp.size = 4096;
		hp.buff = (char *)malloc(4096);
		memset( hp.buff,0,4096);

		http_addline( &hp,HTTP_OK_STR,strlen(HTTP_OK_STR) );
		http_addline( &hp,"Content-Type: text/html",23);
		http_addline( &hp,"Server: nginx/1.0.14",20);
		http_addline( &hp,"Connection: keep-alive",22);
		//Date: Wed, 24 Apr 2019 01:23:12 GMT)

		char buffer[256];
		int x = read(fd,buffer,256);
		char buff[128];
		memset(buff,0,sizeof(buff));
		sprintf(buff,"Content-Length: %d",x);

		http_addline(&hp,buff,strlen(buff));
		http_endline(&hp);
		http_addline(&hp,buffer,x);
		//http_endline(&hp);
		log_print("%s\n",hp.buff);
		send( pconn->fd,hp.buff,hp.pos,0 );
		close(fd);
	}else{
		char buff[] = "HTTP/1.1 404 Not Found\r\nConetne-Length: 0\r\n\r\n";
		log_print("404 not found\n");
		send( pconn->fd,buff,strlen(buff),0 );
	}*/


	return 0;
}

int analysis_http( struct connection *pconn ){
	int idx;
	int ret;

	if( pconn->stat == HTTP_HEAD_NONE ){
		idx = search_pattern( pconn->buffer + pconn->buffer_start,pconn->buffer_pos - pconn->buffer_start,"\r\n\r\n",4,edl_next );
		if( -1 == idx ){
			pconn->stat = HTTP_HEAD_NOT_FULL;
			pconn->info1 = pconn->buffer_pos - 3;
			if( pconn->info1 < 0 )
				pconn->info1 = 0;
			return -1;
		}else{
			pconn->stat = HTTP_HEAD_FULL;
			pconn->info1 = idx + 3;
		}
	}else if( pconn->stat == HTTP_HEAD_NOT_FULL ){
		idx = search_pattern( pconn->buffer + pconn->info1,pconn->buffer_pos - pconn->info1,"\r\n\r\n",4,edl_next );
		if( -1 == idx ){
			pconn->info1 = pconn->buffer_pos - 3;
			if( pconn->info1 < 0 )
				pconn->info1 = 0;
			return -1;
		}else{
			pconn->stat = HTTP_HEAD_FULL;
			pconn->info1 = idx + 3;
		}
	}else{
		assert( pconn->stat == HTTP_HEAD_FULL );
	}

	ret = handle_http_head( pconn,pconn->buffer,pconn->info1 - pconn->buffer_start + 1);

	if( !ret ){
		if( pconn->info1 + 1 == pconn->buffer_pos )
			log_print("<<<<<<<<<<<<<clen buffer\n");
		pconn->buffer_pos = pconn->buffer_start = pconn->info1 = 0;
		pconn->stat = HTTP_HEAD_NONE;
	}

	return 0;
}

//TODO allocate buffer from init to there
//TODO timeout
void event_read_http( struct event *pev ){
	int nRead;
	int ret;
	struct connection *pconn = pev->conn;


	log_print("read request\n");
	nRead = read( pconn->fd, pconn->buffer + pconn->buffer_pos, pconn->buffer_size - pconn->buffer_pos );

	if( nRead < 0 ){
		printf("Error Read %d\n",errno );
		epoll_ctl( epoll_fd, EPOLL_CTL_DEL,pconn->fd,NULL );
	}else if( 0 == nRead ){
		epoll_ctl( epoll_fd, EPOLL_CTL_DEL,pconn->fd,NULL );
		close( pconn->fd );
		log_print("close pconn %s:%d\n",inet_ntoa(pconn->sa.sin_addr),ntohs(pconn->sa.sin_port));
	}else{
		pconn->buffer_pos += nRead;
		ret = analysis_http( pconn );
		log_print("analysis ret = = = = = = = =%d\n",ret);
	}

	return;
}


void event_read_mqtt( struct event *pev ){
	printf("TODO read\n");

	int nRead;
	int ret;
	struct connection *pconn = pev->conn;


	nRead = read( pconn->fd, pconn->buffer + pconn->buffer_pos, pconn->buffer_size - pconn->buffer_pos );


	if( nRead < 0 ){
		printf("Error Read %d\n",errno );
		epoll_ctl( epoll_fd, EPOLL_CTL_DEL,pconn->fd,NULL );
	}else if( 0 == nRead ){
		//TODO close
		//printf("close\n");
		//epoll_ctl( epoll_fd, EPOLL_CTL_DEL,pconn->fd,NULL );
	}else{

		pconn->buffer_pos += nRead;
		//if( MQTT_FIX_HEAD_NONE == pconn->stat ){
		ret = analysis_mqtt( pconn );
		//}

	}

	return;
}

int init_ipc(){
	int shmid = shmget(0x2234,4096, IPC_CREAT | 0666);
	if( -1 == shmid ){
		log_print("shm create error\n");
		return -1;
	}
	void *p = shmat(shmid, NULL, 0);
	if( !p ){
		log_print("shmat error\n");
		return -2;
	}

	mutex = (pthread_mutex_t *)p;

	pthread_mutexattr_init(&mutexAttr);
	pthread_mutexattr_setpshared(&mutexAttr,PTHREAD_PROCESS_SHARED);
	if( pthread_mutex_init(mutex,&mutexAttr) ){
		log_print("mutex_init error\n");
		return -3;
	}

	return 0;
}

struct connection *init_client_fd( struct listening *plisten,struct sockaddr_in *psa,int client_fd ){

	struct event *pev = (struct event *)malloc( sizeof(struct event) );
	struct connection *pconn = (struct connection *)malloc( sizeof(struct connection) );

	if( !pconn || !pev ){
		if( pconn )
			free( pconn );
		if( pev )
			free( pev );
		log_print("malloc fail!\n");
		return NULL;
	}

	memcpy( &(pconn->sa),psa,sizeof(pconn->sa) );

	pev->conn = pconn;
	pev->handler = event_read_mqtt;

	pconn->fd = client_fd;
	pconn->read_event = pev;
	pconn->write_event = NULL;
	pconn->listen = plisten;
	pconn->ref = 0;
	pconn->info1 = 0;
	pconn->info2 = 0;
	pconn->stat = 0;

	pconn->buffer = malloc( BUFFER_DEFAULT_SIZE );
	if( !pconn->buffer ){
		log_print("malloc buffer fail\n");
		free( pev );
		free( pconn );
		return NULL;
	}

	pconn->buffer_pos = 0;
	pconn->buffer_start = 0;
	pconn->buffer_size = BUFFER_DEFAULT_SIZE;

	atomic_incl(pconn->ref);

	return pconn;
}

int init_new_client(){

}

void event_accept( struct event *pev ){
	struct sockaddr_in sa;
	socklen_t len = sizeof(sa);

	do{
		int cli_fd = accept( pev->conn->fd,(struct sockaddr *)&sa,&len );

		if( -1 == cli_fd ){
			if( errno == 11 )
				zlog_info(zc,"accept read over");
			else
				zlog_error(zc,"accept err %d",errno );
			return;
		}

		zlog_info(zc,"cid:%d  %s:%d connect",g_cid,inet_ntoa(sa.sin_addr),ntohs(sa.sin_port));
		struct connection *pconn = init_client_fd( pev->conn->listen,&sa,cli_fd );

		if( !pconn ){
			close(cli_fd);
			zlog_error(zc,"init client_fd err");
			return;
		}

		struct epoll_event ee;
		ee.events = EPOLLIN | EPOLLET;
		ee.data.ptr = (void *)pconn;
		if( -1 == epoll_ctl( epoll_fd, EPOLL_CTL_ADD,cli_fd,&ee ) ){
			zlog_error(zc,"epoll_ctl add cli_fd fail!");
			close(cli_fd);
			free(pconn->read_event);
			free(pconn);
			return;
		}

		assert(holdlock);
		//unlock_mutex();
	}while(0);
}


int init_listening(){
	listen_fd = socket( AF_INET, SOCK_STREAM, 0 );

	if( -1 == listen_fd ){
		zlog_error(zc,"listen_fd create fail!");
		return -1;
	}

	if( -1 == SetNonBlock( listen_fd ) ){
		zlog_error(zc,"listen_fd set nonblock fail!");
		close(listen_fd);
		return -2;
	}

	g_listening.sa.sin_family = AF_INET;
	g_listening.sa.sin_port = htons(7070);
	g_listening.sa.sin_addr.s_addr = inet_addr("192.168.2.222");

	g_listening.socklen = sizeof(g_listening.sa);

	g_listening.listen_fd = listen_fd;

	if( bind( g_listening.listen_fd,(struct sockaddr *)&g_listening.sa,g_listening.socklen ) ){
		printf("bind fail!");
		close(listen_fd);
		return -3;
	}

	g_listening.backlog = 16;

	struct event *pev = (struct event *)malloc( sizeof(struct event) );
	struct connection *pconn = (struct connection *)malloc( sizeof(struct connection) );

	if( !pconn || !pev ){
		if( pconn )
			free(pconn);
		if( pev )
			free(pev);
		zlog_error(zc,"malloc fail!");
		close(listen_fd);
		return -4;
	}

	pev->conn = pconn;
	pev->handler = event_accept;

	pconn->fd = g_listening.listen_fd;
	pconn->read_event = pev;
	pconn->write_event = NULL;
	pconn->listen = &g_listening;
	pconn->ref = 0;

	atomic_incl(pconn->ref);

	g_listening.conn = pconn;

	listen( g_listening.listen_fd,g_listening.backlog );

	return 0;
}

int enable_listening(){
	struct epoll_event ee;
	ee.events = EPOLLIN;
	ee.data.ptr = (void *)g_listening.conn;

	if( -1 == epoll_ctl( epoll_fd, EPOLL_CTL_ADD,g_listening.listen_fd,&ee ) ){
		zlog_error(zc,"epoll_ctl add listen_fd fail! %d",errno );
		close(listen_fd);
		return -1;
	}
	return 0;
}

int disable_listening(){
	if( -1 == epoll_ctl( epoll_fd, EPOLL_CTL_DEL,g_listening.listen_fd,NULL ) ){
		zlog_error(zc,"epoll_ctl del listen_fd fail! %d",errno );
		close(listen_fd);
		return -1;
	}
	return 0;
}

int init_epoll(){
	epoll_fd = epoll_create( MAX_CONNECTION_NUM/2 );

	if( -1 == epoll_fd ){
		zlog_error(zc,"epoll_fd create fail!");
		return -1;
	}

	pevent_ret = malloc( sizeof(struct epoll_event) * MAX_EPOLL_WAIT_NUM );

	if( !pevent_ret ){
		zlog_error(zc,"malloc fail0!");
		return -1;
	}

	return 0;
}


int try_lock_mutex(){
	int ret = pthread_mutex_trylock(mutex);
	return ret;
}

int unlock_mutex(){
	int ret = pthread_mutex_unlock(mutex);
	return ret;
}

int handle_event_entity(){
	int i;
	int ret;

	ret = epoll_wait( epoll_fd,pevent_ret,MAX_EPOLL_WAIT_NUM,timeout );

	if( -1 == ret ){
		zlog_error(zc,"epoll_wait fail!");
		return -3;
	}

	if( 0 == ret ){
		return 0;
	}

	//handle event
	for( i = 0; i < ret; i++ ){
		struct connection *pconn = (struct connection *)pevent_ret[i].data.ptr;
		if( !pconn ){
			zlog_error(zc,"handle event get ptr fail!\n");
			return -1;
		}

		if( pevent_ret[i].events & EPOLLIN){
			pconn->read_event->handler( pconn->read_event );
		}else if( pevent_ret[i].events & EPOLLOUT){

		}
	}
#if 0
	if( holdlock )
		
(1);
#endif
	return 0;

}

int getDataBase(int cid){
	char user[16];
	sprintf(user,"serv_cpu%d",cid);
	sqlConn = init_and_connect(user,"xs1234");
	return 0;
}

int getZlog(int cid){
	int ret;
	char logname[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

	sprintf( logname,"cpu%d",cid );
	ret = zlog_init("./zlog.conf");

	if( ret ){
		printf("zlog init failed\n");
		return -1;
	}

	zc = zlog_get_category(logname);
	if (!zc) {
		printf("get zlogname fail\n");
		zlog_fini();
		return -2;
	}

	return 0;
}



#define LOOPERR_DATABASE_CONN		0x1
#define LOOPERR_INIT_EPOLL			0x2
#define LOOPERR_INIT_LOG			0x3

#define LOOPERR_LISTENING			0x4

void dp_start(){

	return;
}

sighandler_t oriIntFun = NULL;

void servInt( int sig ){
	char sql[128];
	memset( sql,0,sizeof(sql) );
	sprintf( sql,"delete from Subscribe where cid=%d",g_cid);
	exec_sql_str( sqlConn,sql );

	memset( sql,0,sizeof(sql) );
	sprintf( sql,"delete from LoginUser where cid=%d",g_cid);
	exec_sql_str( sqlConn,sql );

	oriIntFun(sig);
	return;
}

int start_event_loop(int cid){

	int i = 0;
	int ret = 0;
	g_cid = cid;

	if( getZlog(cid) ){
		return -LOOPERR_INIT_LOG;
	}

	zlog_info(zc,"cid:%d start",cid);

	getDataBase(cid);
	if( NULL == sqlConn ){
		zlog_error(zc,"sql connect error");
		return -LOOPERR_DATABASE_CONN;
	}

	chdir("/home/sai/WebHome");
	//chmod("..",0);

	ret = init_epoll();
	if( 0 != ret )
		return -LOOPERR_INIT_EPOLL;

	oriIntFun = signal( SIGINT,servInt );

	while(1){
		if( !try_lock_mutex() ){
			if( 1 == holdlock )
				goto _handle;
			holdlock = 1;
			if( enable_listening() )
				return -LOOPERR_LISTENING;
		}else{
			if( 1 == holdlock ){
				if( disable_listening() )
					return -LOOPERR_LISTENING;
				holdlock = 0;
			}
		}
_handle:
		handle_event_entity();
		if( 1 == holdlock ){
			unlock_mutex();
		}
	}

	return 0;
}



int main(){

	int i = 0;
	int ret = 0;
	long ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	ret = init_ipc();
	if( ret )
		return ret;

	ret = init_listening();
	if( 0 != ret )
		return -2;

	int cid = 0;

#if 1
	ncpus = 1;
#endif

	while( i < ncpus ){
		int pid = fork();
		if( 0 == pid ){
			if( set_affinity( cid ) )
				return -1;

			ret = start_event_loop(cid);
			return 0;
		}else{
			cid++;
		}
		i++;
	}

	while(1);
}

#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
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
#include"Base64.h"
#define HP_MAX_LEN 8187
struct http_pack{
    int pos;
    char buff[8188];
};


int http_addline( struct http_pack *hp,char *newline ){

    int current_pos = hp->pos;
    int newline_len = strlen(newline);

    if( current_pos + newline_len + 2 >= HP_MAX_LEN )
        return -1;
    if( (current_pos <= 4) && (current_pos != 0) )
        return -1;

    if( hp->pos == 0 ){
        memcpy( hp->buff,newline,newline_len );
    }else{
        current_pos -= 2;
        memcpy( hp->buff + current_pos,newline,newline_len );
    }

    current_pos += newline_len;
    memcpy( hp->buff + current_pos,"\r\n\r\n",4 );
    current_pos += 4;

    hp->pos = current_pos;
    return 0;

}

int next[32];
void match_pre( char *pattern,int *next,int pattern_len ){

    int matched = 0;
    int begin = 1;

    next[0] = 0;
    while( begin + matched < pattern_len ){
        if( pattern[begin + matched ] == pattern[matched] ){
            matched++;
            next[begin + matched - 1] = matched;
        }else{
            if( matched == 0 ){
                begin++;
            }else{
                begin += matched - next[ matched - 1];
                matched = next[ matched - 1];
            }
        }
    }
    return;
}

int match( char *str,char *pattern,int *len ){

    int pattern_len = strlen( pattern );
    int str_len = strlen(str);

    int matched = 0;
    int begin = 0;
    char *p = NULL;

    if( pattern_len > 32 )
        return -1;

    match_pre( pattern,next,pattern_len );

    while( begin + matched < str_len ){
        if( pattern[matched] == str[begin + matched] ){
            matched++;
            if( matched == pattern_len ){
                p = str + begin + matched;
                while( *p != '\r' || *(p + 1) != '\n')
                    p++;
                *len = p - (str + begin);
                return begin;
            }
        }else{
            if( matched == 0 ){
                begin++;
            }else{
                begin += matched - next[ matched - 1];
                matched = next[ matched - 1];
            }
        }
    }
    return -1;

}

char *line_match( char *str,char *pattern ){
    int len;
    int index = match( str,pattern,&len );
    if( index == -1 )
        return NULL;

    char *buff = (char *)malloc( sizeof(char) * len + 1 );
    memcpy( buff,&str[index],len );
    buff[len] = '\0';

    return buff;
}

struct rtpHeader{
    unsigned char cc:4;
    unsigned char x:1;
    unsigned char p:1;
    unsigned char V:2;

    unsigned char pt:7;
    unsigned char m:1;

    unsigned short seq;
    unsigned int timestamp;
    unsigned int SSRC;
};

struct nalu{
    unsigned char type:5;
    unsigned char nri:2;
    unsigned char f:1;
};


char start[] = {0x00,0x00,0x00,0x01};
unsigned sps_size;
unsigned pps_size;
char base64sps[] = "Z0LAHtkDxWhAAAADAEAAAAwDxYuS";
char base64pps[] = "aMuMsg==";



unsigned short get_interleave( int sfd,char *buff,int buffsize ){

    int ret;
    assert( buffsize >= 4 );
    ret = recv( sfd,buff,4,0 );
    assert( ret == 4 );

    return ntohs(*(unsigned short *)(buff + 2));
}


void recv_rtp_head( int sfd,char *buff,int buffsize ){
    int ret;
    assert( buffsize >= 12 );
    ret = recv( sfd,buff,12,0 );
    assert( ret == 12 );

    return;
}


void get_nal_head( int sfd,char *buff,int buffsize ){

    int ret;
    assert( buffsize >= 1 );
    ret = recv( sfd,buff,1,0 );
    assert( ret == 1 );

    return;
}


struct fu{
    unsigned char type:5;
    unsigned char r:1;
    unsigned char e:1;
    unsigned char s:1;
};

void recv_and_write( struct nalu *pnal,int sfd,int fd,int length ){

    int ret;
    int recv_len;
    char buff[4096];
    char i_fl[] = {0x65};

    if( pnal->type != 28 ){
        write( fd,start,4 );
        write( fd,pnal,1 );
    }else{
        printf("28 28 28 28 28\n");
        ret = recv( sfd,buff,1,0 );
        assert( ret == 1 );
        length -= 1;
        struct fu *pfu = (struct fu *)buff;
        if( pfu->s ){
            write( fd,start,4 );
            write( fd,i_fl,1 );
            printf("FU's type = %x\n",pfu->type);
        }
    }

    while( length ){
        recv_len = 4096<length?4096:length;
        ret = recv( sfd,buff,recv_len,0 );
        assert( ret == recv_len );
        write( fd,buff,ret );
        length -= ret;
    }

}

void drop_rtcp( int sfd,int length ){
    printf("drop length = %d\n",length);
    char buff[1024];
    int recv_len,ret;
    while( length ){
        recv_len = 1024<length?1024:length;
        ret = recv( sfd,buff,recv_len,0 );
        assert( ret == recv_len );
        length -= ret;
    }
}

void handle_atm( int sfd,int fd ){

    char buff[32];
    int ret;
    int length = get_interleave( sfd,buff,32 );
    
    if( buff[1] % 2 ){
        drop_rtcp( sfd,length );
        return;
    }

    recv_rtp_head( sfd,buff,32 );
    length -= 12;
    struct rtpHeader *prtp = (struct rtpHeader *)buff;
    printf("--------------------------\n");
    printf("ssrc = %x\n",ntohl(prtp->SSRC));
    printf("seq = %d\n",ntohs(prtp->seq));
    get_nal_head( sfd,buff,32 );
    length -= 1;

    struct nalu *pnal = (struct nalu *)buff;
    recv_and_write( pnal,sfd,fd,length );

    return;
}


int main(){

    unsigned char *sps = base64Decode( base64sps,sps_size );
    unsigned char *pps = base64Decode( base64pps,pps_size );

    struct http_pack send_pack;
    send_pack.pos = 0;
    struct sockaddr_in sa;
    int sfd = socket(AF_INET,SOCK_STREAM,0);
    int ret = -1;

    sa.sin_family = AF_INET;
    sa.sin_port = htons(554);
    sa.sin_addr.s_addr = inet_addr("184.72.239.149");


    ret = connect( sfd,(struct sockaddr *)&sa,sizeof(sa) );

    if( ret < 0 ){
        printf("connect error,%d\n",errno);
        return -1;
    }
    printf("connect succ\n");
    char buff[40960];


    //send describe packet
    http_addline(&send_pack,(char *)"DESCRIBE rtsp://184.72.239.149/vod/mp4://BigBuckBunny_175k.mov RTSP/1.0");
    http_addline(&send_pack,(char *)"User-Agent: LIVE555 Streaming Media v2008.04.09");
    http_addline(&send_pack,(char *)"Cseq: 1");
    http_addline(&send_pack,(char *)"Accept: application/sdp");
    printf("%s\n",send_pack.buff);
    send( sfd,send_pack.buff,send_pack.pos,0);
    ret = recv( sfd,buff,40960,0 );
    buff[ret] = '\0';
    printf("%s\n",buff);


    //send setup packet
    memset( &send_pack,0,8192 );
    http_addline(&send_pack,(char *)"SETUP rtsp://184.72.239.149/vod/mp4://BigBuckBunny_175k.mov/trackID=2 RTSP/1.0");
    http_addline(&send_pack,(char *)"Transport: RTP/AVP/UDP;unicast;");
    http_addline(&send_pack,(char *)"Cseq: 2");
    printf("%s\n",send_pack.buff);
    send( sfd,send_pack.buff,send_pack.pos,0);
    ret = recv( sfd,buff,40960,0 );
    buff[ret] = '\0';
    printf("%s\n",buff);


    char *p = line_match(buff,(char *)"Session:");
    char Session[128];
    for( int i = 0; ; i++ ){
        if( p[i] == ';'){
            Session[i] = '\0';
            break;
        }
        Session[i] = p[i];
    }


    //send play packet
    memset( &send_pack,0,8192 );
    http_addline(&send_pack,(char *)"PLAY rtsp://184.72.239.149/vod/mp4://BigBuckBunny_175k.mov/trackID=2 RTSP/1.0");
    http_addline(&send_pack,(char *)"Cseq: 3");
    http_addline(&send_pack,(char *)Session);
    http_addline(&send_pack,(char *)"Range: npt=0.000-");
    printf("%s\n",send_pack.buff);
    send( sfd,send_pack.buff,send_pack.pos,0);
    ret = recv( sfd,buff,40960,0 );
    buff[ret] = '\0';
    printf("%s\n",buff);


    int fd = open("./s1.h264",O_CREAT | O_WRONLY,0666 );
    assert( fd > 0 );

    char sps_fl[] = {0x67};
    char pps_fl[] = {0x68};
    write( fd,start,4 );
    write( fd,sps,sps_size );
    printf("sps size = %d\n",sps_size);

    write( fd,start,4 );
    write( fd,pps,pps_size );
    printf("pps size = %d\n",pps_size);

    int cnt = 0;
    while(1){

            handle_atm( sfd,fd );
            usleep(150000);
            cnt++;
            if( cnt > 3000 )
                break;
    }

    close(sfd);

    return 0;
}


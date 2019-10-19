#include<iostream>
#include<cmath>
#include<vector>
#include<cstdlib>
#include<cstring>
#include<cstdio>
#include<unistd.h>
#include<queue>
#include<algorithm>
#include<assert.h>
using namespace std;

#define M	25
char map[M][M];

struct node{
	int ix;
	int jx;

	int G;
	int H;
	int F;

	int inopen;

	struct node *par;
};

struct node node_map[M][M];

int targeti = 7;
int targetj = 7;

int starti = 2;
int startj = 2;

void init(){
	for( int i = 0; i < M; i++ ){
		for( int j = 0; j < M; j++ ){
			map[i][j] = ' ';
			node_map[i][j].ix = i;
			node_map[i][j].jx = j;
			node_map[i][j].par = NULL;

			node_map[i][j].G = 0x3f3f3f3f;
			node_map[i][j].H = 0x3f3f3f3f;
			node_map[i][j].F = 0x3f3f3f3f;

			node_map[i][j].inopen = 0;
		}
	}
	for( int i = 0; i < M; i++ ){
		map[i][0] = map[i][M - 1] = '*';
		map[M - 1][i] = map[0][i] = '*';
	}

	map[starti][startj] = 's';
	map[targeti][targetj] = 'e';

	map[5][2] = 'w';
	map[5][3] = 'w';
	map[5][4] = 'w';
	map[5][5] = 'w';
}


int calc_H( struct node *p,int di,int dj ){
	return  abs(p->ix-di) + abs(p->jx-dj);
}

int calc_G( struct node *p ){
	return abs(targeti - p->ix) + abs(targetj - p->jx );
}

int calc_dis( int i1,int j1,int i2,int j2 ){
	int dx = i1 - i2;
	int dy = j1 - j2;
	int d2 = dx * dx + dy * dy;
	
	return 0;
}

void print_map(){
	for( int i = 0; i < M; i++ ){
		for( int j = 0; j < M; j++ ){
			cout<<map[i][j];
		}
		cout<<endl;
	}
}

class node_comp{
	public:
		bool operator()( struct node a,struct node b ){
			return a.F > b.F;
		}
};

int di[] = {-1,0,1,0};
int dj[] = {0,1,0,-1};

bool operator==( struct node a,struct node b ){
	if( a.ix == b.ix && a.jx == b.jx )
		return 1;
	return 0;
}


struct node *heap[1024];
int heapsize;
void qpush( struct node *pval ){

	int i = heapsize++;
	int p;

	while( i > 0 ){
		p = ((p - 1) >> 1);
		if( heap[p]->F >= pval->F ){
			heap[i] = heap[p];
			i = p;
		}else
			break;
	}

	heap[i] = pval;
	pval->inopen = i;
}

struct node *qpop(){
	struct node *ret = heap[0];
	struct node *pt = heap[--heapsize];

	int i = 0,l = 1,r = 2,mi;

	while( l < heapsize ){
		mi = i;
		if( heap[l]->F < pt->F )
			mi = l;
		if( r < heapsize && heap[r]->F < pt->F )
			mi = r;
		if( mi != i ){

			heap[i] = heap[mi];

			i = mi;
			l = (i << 1) + 1;
			r = l + 1;
		}else
			break;
				
	}

	heap[mi] = pt;

	ret->inopen = -1;
	return ret;
}

void adjust( int idx,int newF ){
	int i,p;
	if( newF > heap[idx]->F ){
		assert(0);
	}else if( newF < heap[idx]->F ){
		i = idx;
		struct node *pt = heap[idx];

		while( i > 0 ){
			p = ((i - 1) >> 1);
			if( heap[p]->F >= newF ){
				heap[i] = heap[p];
				i = p;
			}else
				break;
		}

		heap[i] = pt;
		pt->inopen = i;
		pt->F = newF;
		
	}else{

	}
}

int main(){

	init();

	vector<struct node*> close;

	node_map[starti][startj].G = calc_G( &node_map[starti][startj] );
	node_map[starti][startj].H = 0;
	node_map[starti][startj].F = 0;

	qpush( &node_map[starti][startj] );

	while(1){
		system("clear");
		print_map();
		sleep(1);

		struct node *pcur = qpop();
		close.push_back( pcur );

		map[pcur->ix][pcur->jx] = 'n';


		int ti,tj;

		for( int i = 0; i < 4; i++ ){
			ti = pcur->ix + di[i];
			tj = pcur->jx + dj[i];
			if( ti < 0 || ti == M )
				continue;
			if( tj < 0 || tj == M )
				continue;
			if( ti == targeti && tj == targetj ){
				cout<<"find"<<endl;
				return 0;
			}
			if( map[ti][tj] != 'w' ){
				if( close.end() != find( close.begin(),close.end(),&node_map[ti][tj] ) ){
					continue;
				}else{
					int newH =  pcur->H + 1;
					int newG = calc_G( &node_map[ti][tj] );

					if( node_map[ti][tj].inopen != - 1 ){

						node_map[ti][tj].G = newG;
						node_map[ti][tj].H = newH;
						node_map[ti][tj].F = newG + newH;
						node_map[ti][tj].par = pcur;

						qpush( &node_map[ti][tj] );
					}else{
						if( newH + newG < node_map[ti][tj].F ){
							adjust( node_map[ti][tj].inopen,newH + newG );
							node_map[ti][tj].par = pcur;
						}
					}
				}
			}
		}

	}


	return 0;
}

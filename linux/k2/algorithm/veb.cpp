#include<iostream>
#include<math.h>
using namespace std;


int arr[8] = {0};


int count = 0;
int find3(){
    for( int i = 0; i < 5; i++ ){
        if( (arr[i] == 0) && (arr[i + 1] == 0) ){
            if( (arr[i + 2] == 0 ) && (arr[i + 3] == 0) )
                return 0;
        }
    }
    for( int i = 0; i < 6; i++ ){
        if( (arr[i] == 0) && (arr[i + 1] == 0) && (arr[i + 2] == 0) ){
            if(i == 5)
                return 1;
            if( arr[i + 3] == 1)
                return 1;
        }
    }
    return 0;
}

int fc( int deep ){
    if( deep == 8 ){
        if( find3() )
            count++;
        return 0;
    }

    arr[deep] = 0;
    fc( deep + 1);
    arr[deep] = 1;
    fc( deep + 1);

    return 0;
}

#define high(x,u) (x/(int)pow(u,0.5))
#define low(x,u) (x%(int)pow(u,0.5))
#define index(h,l,u) (h*u + l)

struct raw_veb{
    int degree;
    int A[2];
    struct raw_veb *summary;
    struct raw_veb **cluster;
};

struct raw_veb *create_node( int degree ){
    struct raw_veb *pnew = new struct raw_veb;
    pnew->degree = degree;
    pnew->summary = new struct raw_veb;
    pnew->cluster = (struct raw_veb **)malloc( sizeof(struct raw_veb *) * degree );
}

int raw_veb_member( struct raw_veb *root,int i ){
    if( root->degree == 2 )
        return root->A[i];

    int degree = root->degree;
    int h = high(i,degree);
    int l = low(i,degree);

    return raw_veb_member( root->cluster[h],l );
}

int raw_veb_min( struct raw_veb *root ){
    if( root->degree == 2 ){
        if( root->A[0] == 1 )
            return 0;
        if( root->A[1] == 1 )
            return 1;
        return -1;
    }

    int min_cluster =  raw_veb_min( root->summary );
    if( min_cluster == -1 )
        return -1;
    int offset = raw_veb_min( root->cluster[min_cluster] );
    return index(min_cluster,offset,root->degree);
}

int raw_veb_successor( struct raw_veb *root,int data ){
    if( root->degree == 2 ){
        if( (data == 0) && (root->A[1] == 1) )
            return 1;
        return -1;
    }

    int offset = raw_veb_successor( root->cluster[high(data,root->degree)],low(data,root->degree) );
    if( offset != -1 )
        return index( high(data,root->degree),offset );

    int min_cluster = raw_veb_successor( root->summary,high(data,root->degree) );
    if( min_cluster == -1 )
        return -1;

    offset = raw_veb_min( root->cluster[min_cluster] );

    return index( min_cluster,offset,root->degree );
}

void raw_veb_insert( struct raw_veb *root,int i ){
    if( root->degree == 2 ){
        root->A[i] = 1;
        return;
    }

    raw_veb_insrt( root->summary,high(i,root->degree) );
    raw_veb_insert( root->cluster[high(i,root->degree)],low(i,root->degree) );

    return;
}

int main(){


    return 0;
}

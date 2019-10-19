#include<iostream>

using namespace std;

//分支因子t,除了root外至少要t-1个关键字
//2t-1个关键字为满状态
//p0  key0   p1   key1.......pn   keyn   pn+1


struct node{
    int n;
    int leaf;
    int key[512];
    struct node *p[512];
};

struct node *T;
int t;

int search( struct node *root,int key,struct node *p,int *pidx){
    int i = 0;
    for( ; i < root->n; i++ ){
        if( root->key[i] >= key )
            break;
    }

    if( (i < root->n) && key == root->key[i] ){
        *p = *root;
        *pidx = i;
        return 1;
    }

    if( root->leaf )
        return 0;

    return search( root->p[i],key,p,pidx );
    
}

struct node *create(){
    struct node *pnew = new struct node;
    pnew->leaf = 1;
    pnew->n = 0;
}

int split( struct node *pnode,int idx ){
    struct node *pc = pnode->p[ idx ];
    struct node *pnew = create();

    int skey = pc->key[t - 1];

    //新结点信息的建立
    pnew->n = t - 1;
    pnew->leaf = pc->leaf;
    int i = 0;
    for( ; i < t - 1; i++ ){
        pnew->key[i] = pc->key[ t + i ];
        pnew->p[i] = pc->p[ t + i ];
    }
    pnew->p[t - 1] = pc->p[ 2 * t ];
    pc->n = t - 1;

    //处理结点的上移
    //原本idx的位置改为新关键字
    pnode->n++;
    for( i = pnode->n - 1; i >= idx + 1 ; i-- ){
        pnode->key[i] = pnode->key[i - 1];
    }
    pnode->key[ idx ] = skey;

    //处理指针
    for( i = pnode->n; i >= idx + 2 ; i-- ){
        pnode->p[i] = pnode->p[i - 1];
    }
    pnode->p[ idx + 1 ] = pnew;

    return 0;
}




int split2( struct node *pnode,int idx ){
    struct *pc = pnode->p[ idx ];
    struct node *pnew = create();

    pc->n = pnew->n = t - 1;
    pnew->leaf = pc->leaf;

    for( int i = 0; i < t - 1; i++ ){
        pnew->key[i] = pc->key[t + i];
        pnew->p[i] = pc->key[t + i];
    }
    pnew->p[t - 1] = pc->p[2 * t];

    pnode->n++;
    for( int i = pnode->n - 1; i >= idx + 1; i-- ){
        pnode->key[i] = pnode->p[i - 1];
    }
    pnode->key[idx] = pc->key[t - 1];

    for( int i = pnode->n; i >= idx + 2;i-- ){
        pnode->p[i] = pc->p[i - 1];
    }
    pnode->p[idx + 1] = pnew;


    return 0;
}

int insert_nofull( struct node *pnode,int key ){

    int degree = pnode->n - 1;

    if( pnode->leaf ){
        while( (degree >= 0) && (k < pnode->key[ degree ]) ){
            pnode->key[degree + 1] = pnode->key[degree];
            degree--;
        }
        pnode->n++;
        pnode->key[ degree + 1 ] = key;
        return 0;
    }else{
        while( (degree >= 0) && (k < pnode->key[ degree ]) ){
            degree--;
        }
        degree++;
        if( pnode->p[degree]->n == 2 * t - 1 ){
            split( pnode,degree );
            //下结点上升，所以要再判断一次
            if( key > pnode->key[degree] )
                degree++;
        }

        insert_nofull( pnode->p[degree],key );
    }

    return 0;
}

int insert( struct node **T,int key ){
    struct node *root = *T;
    if( root->n == 2 * t - 1 ){
        struct node *pnew = create();
        (*T) = pnew;
        pnew->leaf = 0;
        pnew->n = 1;

        pnew->p[0] = root;
        split( pnew,0 );
        insert_nofull( pnew,key );
    }else{
        insert_nofull( root,key );
    }

    return 0;
}

int main(){

    return 0;
}

#include<iostream>
#include<assert.h>
using namespace std;

#define T 3

struct BtreeNode{
    int key;
    int count;
    int leaf;
    int chd_key[2 * T - 1];
    struct BtreeNode *chd_ptr[2 * T];
};

struct Btree{
    struct BtreeNode *root;
};

void DiskR(){}
void DiskW(){}

void split( struct BtreeNode *node,int idx ){
    struct BtreeNode *pchd = node->chd_ptr[idx];
    assert( pchd->count == 2 * T - 1 );

    int i = 0;
    int cur_count = node->count;
    struct BtreeNode *rpart = new struct BtreeNode;
    rpart->count = T - 1;
    rpart->leaf = pchd->leaf;

    for( i = 0; i < T - 1; i++ ){
        rpart->chd_key[i] = pchd->chd_key[T + i];
        rpart->chd_ptr[i] = pchd->chd_ptr[T + i];
    }
    rpart->chd_ptr[i] = pchd->chd_ptr[T + i];

    for( int i = cur_count; i > idx; i-- ){
        node->chd_key[i] = node->chd_key[i - 1];
    }
    node->chd_key[idx] = pchd->chd_key[T - 1];

    for( int i = cur_count + 1; i > idx + 1; i-- ){
        node->chd_ptr[i] = node->chd_ptr[i - 1];
    }
    node->chd_ptr[idx + 1] = rpart;

    node->count += 1;
    return;
}

struct BtreeNode *search( struct BtreeNode *BN,int key,int &idx ){
    struct BtreeNode *node = BN;
    int i = 0;

    //TODO:leaf
    while( i < node->count && node->chd_key[i] < key )
        i++;
    if( i == node->count )
        return search( node->chd_ptr[node->count],key,idx );
    if( node->chd_key[i] == key ){
        idx = i;
        return node;
    }

    return search( node->chd_ptr[i],key,idx );
}

void insert_no_full( struct BtreeNode *node,int key ){

    int i = 0;

    if( node->leaf ){
        i = node->count;
        while( i > 0 && node->chd_key[i - 1] > key ){
            node->chd_key[i] = node->chd_key[i - 1];
            i--;
        }
        node->chd_key[i] = key;
        node->count += 1;
        return;
    }

    i = node->count;
    while( i > 0 && node->chd_key[i - 1] > key ){
        i--;
    }

    //keyi > key 分裂后,keyi的值更新，需要再判断一次
    if( node->chd_ptr[i]->count == 2 * T - 1 ){
        split( node,i );
        if( node->chd_key[i] < key )
            i++;
    }
    insert_no_full( node->chd_ptr[i],key );

}

void insert( struct Btree *BT,int key ){
    struct BtreeNode *node = BT->root;

    if( node->count == 2 * T - 1 ){
        struct BtreeNode *newTop = new struct BtreeNode;
        newTop->leaf = 0;
        newTop->count = 0;
        newTop->chd_ptr[0] = node;
        BT->root = newTop;

        split( newTop,0 );
        insert_no_full( newTop,key );
        return;
    }
    insert_no_full( node,key );

    return;
}


struct Btree *create(){
    struct Btree *BT = new struct Btree;
    BT->root = new struct BtreeNode;
    BT->root->count = 0;
    BT->root->leaf = 1;

    return BT;
}


//  idx-1        idx          idx+1
//          lr          rp
//---------------merge---------------
//   idx-1                idx+1
//           lr+idx+rp
//



void del( struct Btree *BT,int key ){


    assert( BT );
    int idx;
    struct BtreeNode *toDel;
    struct BtreeNode *node;

    if( toDel->leaf ){
        //case1:叶结点,删除+挪位
        return;
    }

    //在关键字当前层
    {
        if( toDel->chd_ptr[idx]->count >= T ){
            //case2:非叶，且在此关键字的左子结点关键字数>=T，找前趋,来代替当前结点
        }else if( toDel->chd_ptr[idx + 1]->count >= T ){
            //case3:非叶，且在此关键字的右子结点关键字数>=T，找后继,来代替当前结点
        }else{
            //case4:左右儿子都只有T-1个关键字,合并左子 = 左子 + key[idx] + 右子,则idx+1失去原左子，获取idx的左子代替idx，
            //递归，从左子中删key
        }
    }

    //关键字不在当前层,在idx子树中
    {
        if( node->chd_ptr[idx]->count == T - 1 ){
            //下层结点的关键字数只有T - 1个,需要保证至少T个,否则删除一个之后不满足B树条件
            if( (node->chd_ptr[idx - 1]->count == T - 1) && (node->chd_ptr[idx + 1]->count == T - 1) ){
                //case5:下层结点的相邻兄弟也都只有T - 1个关键字,任选一个合并(加入当前曾的idx号关键字)
            }else{
                //case6:某个相邻兄弟结点b包含T个关键字,将当前层idx号关键字下降至chd_ptr[idx]中,b中最小关键字m提至当前层,
            }
        }
    }





    return;
}


int main(){

    struct Btree *BT = create();
    insert( BT,1 );
    insert( BT,2 );
    insert( BT,3 );
    insert( BT,4 );
    insert( BT,5 );
    insert( BT,6 );
    insert( BT,7 );

    struct BtreeNode *tmp;
    int idx;

    tmp = search( BT->root,4,idx );
    printf("tmp = %p    idx = %d\n",tmp,idx);
    tmp = search( BT->root,5,idx );
    printf("tmp = %p    idx = %d\n",tmp,idx);
    tmp = search( BT->root,7,idx );
    printf("tmp = %p    idx = %d\n",tmp,idx);

    return 0;
}

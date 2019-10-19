#include<iostream>
#include<cstring>

using namespace std;

#define pat_len 6
char pattern[] = "return";

//后缀函数
//该函数对输入串的每一个后缀进行计算，如果后缀等于模式串前缀，记录下来，返回这个最长数
int a( char *src ){
    int len =strlen( src );

    for( int i = 0; i < len; i++ ){
        if( !strncmp( pattern,src + i,len - i) )
            return len - i;
    }
    return 0;
}


//当前文本到T[i]已经匹配了state个字符,在追加a后，计算T[i + 1]的后缀和P的前缀关系
//计算状态state添加一字符后的目标状态
int state_move( int state,char append ){
   char tmp[16];
   int len = state + 1;
   memcpy( tmp,pattern,state);
   tmp[state] = append;
   tmp[len] = '\0';

   return a( tmp );
}

char buff[] = "int solve(int i,int j){if( i < 0 || j < 0)return 0;int ret = f[i][j];if( f[i][j] != -1return f[i][jif( tbl[i][j] == '1' )f[i][j] = 0return ret = solve(i,j-1) + solve(i-1,f[i][j] = ret;return ret;}";

int cache[pat_len + 1][256];


int main(){

    int state = 0;
    memset( cache,-1,sizeof(cache) );
    int len = strlen(buff);

    for( int i = 0; i < len; i++ ){
        char append = buff[i];
        if( cache[state][append] == -1 ){
            cache[state][append] = state_move( state,append );
        }
        state = cache[state][append];
        if( state == pat_len ){
            printf("%d\n",i - pat_len + 1);
        }
    }


    return 0;
}



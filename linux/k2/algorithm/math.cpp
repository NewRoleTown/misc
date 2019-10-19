#include<iostream>
using namespace std;

#if 0

a > b
a = jT
b = kT

a = xb + r
  = xkT + r = jT
  r = (j - xk)T

则r也包含这个最大公约数

a = gi
b = gj
ax + by = g(ix + bj) = s
gi mod g(ix + bj) = 0

s是a和b线性组合集中的最小正元素
s = ax + by
a mod s = a - qs = a - q(ax + by) = a(1 - qx) + b(-qy),
首先0 <= (a mod s) < s
其次ax + by 这种组合方式组合出的最小正整数是s，则a mod s = 0
同理b mod s = 0

gcd(a,b) >= s
(ax + by)%gcd(a,b) = 0
则s <= gcd(a,b);
则s == gcd(a,b)



#endif

#if 0

n个人，第m个出列,假设第一次出列的是k，则余下的n-1个人如下标号
k + 1 -> 0
k + 2 -> 1
..
n - 1 -> n - k - 2
0     -> n - k - 1
..
k - 1 -> n - 2

f(x) = (n + x -k - 1)%(n - 1)
f^-1(x) = (x + n + k + 1)%n

#endif

int gcd( int a,int b ){
    int c = a % b;
    if( c == 0 )
        return b;
    return gcd(b,c);
}

int main(){

    return 0;
}

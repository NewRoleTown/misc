#include<iostream>
using namespace std;

#if 0

a > b
a = jT
b = kT

a = xb + r
  = xkT + r = jT
  r = (j - xk)T

��rҲ����������Լ��

a = gi
b = gj
ax + by = g(ix + bj) = s
gi mod g(ix + bj) = 0

s��a��b������ϼ��е���С��Ԫ��
s = ax + by
a mod s = a - qs = a - q(ax + by) = a(1 - qx) + b(-qy),
����0 <= (a mod s) < s
���ax + by ������Ϸ�ʽ��ϳ�����С��������s����a mod s = 0
ͬ��b mod s = 0

gcd(a,b) >= s
(ax + by)%gcd(a,b) = 0
��s <= gcd(a,b);
��s == gcd(a,b)



#endif

#if 0

n���ˣ���m������,�����һ�γ��е���k�������µ�n-1�������±��
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

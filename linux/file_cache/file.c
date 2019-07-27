1
无O_SYNC O_DIRECT
read()阻塞，write()至页高速缓存就结束
 
2
O_SYNC = 1
写操作阻塞至完成

3
mmap

4
O_DIRECT = 1
不经过页高速缓存

5
async

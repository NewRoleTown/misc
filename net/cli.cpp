#if 0


client(192.168.0.3:100)   ------>     route(8.8.8.8:800)      ---------->   server(1.1.1.1:1111)

    和新的endpoint连接时
    A复用映射关系
        A1当收到来自2.2.2.2:2222来的消息时，无条件转发给client是全锥
        A2如果client给2.2.2.2发过消息则转发，受限锥型
        A3如果client给2.2.2.2:2222发过消息则转发，端口受限型
    B路由器重新选一个端口做映射,对称型


    均假设B是发起方,B要去和A通信
    clientA:upA-------->RouteA:rpA------------->SERVER<----------RouteB:rpB<-----------------clientB:upB
    1.A为全锥，B为对称
    S将RouteA:rpA发给B，B新建映射RouteB:rpB2发udp给RouteA:rpA，且这个映射由于A是全锥可以复用,成功

    2.A为限制锥，B为全锥
    B给S发打洞请求，S转发给A，A拿到B的RouteB:rpB发UDP给B,B是全缀，复用该映射，且通过这个udp包，限制锥A发现自己和B的ip连接过了，于是也能接收B的包，成功

    3.A为限制锥，B为限制锥或端口限制锥
    S将对端信息发给两边，之后
    RouteA:rpA发一个垃圾udp包给RouteB:rpB，RouteB:rpB发一个垃圾udp包给RouteA:rpA,这样，限制缀的限制解除了，之后就当全锥打，成功

    4.A为限制锥，B为对称
    S将B的信息发给A
    A先向B发一个垃圾udp解除限制，之后按情况1打，成功

    5.A为端口限制型，B为全锥
    S将B的RouteB:rpB发给A，A开始给B发udp，这一步同时也解除了限制，成功

    6.A为端口限制，B为限制或者端口限制
    同3,成功

    7.A为端口限制，B为对称
    S将B的信息发给A
    如果按4来打，A向routeB:rpB发一个垃圾udp可以解除A的收routeB:rpB限制，然而，对称型的B要发udp给A的话，要新建映射，因此端口不能复用，则依然存在限制,血崩
    
    8.A为对称，B为对称
    直接血崩

#endif

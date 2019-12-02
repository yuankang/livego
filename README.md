# livego
stream media server use golang


编译
livego$ go build livego.go

运行
livego$ ./livego
2019/12/02 15:18:22 livego.go:65: HttpServer listen on :8888
2019/12/02 15:18:22 livego.go:1712: rtmp server listen on :1935
2019/12/02 15:18:43 livego.go:1743: new rtmp conn: 127.0.0.1_57794.log
2019/12/02 15:18:43 livego.go:1400: new publisher live_yuankang_publisher_127.0.0.1_57794.log
2019/12/02 15:18:58 livego.go:1743: new rtmp conn: 127.0.0.1_58035.log
2019/12/02 15:18:58 livego.go:1415: new player live_yuankang_player_127.0.0.1_58035.log

推流和播放的日志 分别打印到不同的日志文件中。
每个推流和播放，在建立连接的时候就开始产生日志，rtmp握手后会从命名日志。
日志文件名规则：appname_StreamName_发布或播放_远端SocketIp_远端SocketPort.log
日志文件名举例: live_yuankang_publisher_127.0.0.1_57794.log

推流日志
2019/12/02 15:18:43 livego.go:1743: new rtmp conn: 127.0.0.1_57794.log
2019/12/02 15:18:43 livego.go:1400: new publisher live_yuankang_publisher_127.0.0.1_57794.log

播放日志
2019/12/02 15:18:58 livego.go:1743: new rtmp conn: 127.0.0.1_58035.log
2019/12/02 15:18:58 livego.go:1415: new player live_yuankang_player_127.0.0.1_58035.log


推流命令
ffmpeg -re -i RealSteel.mp4 -c:v copy -c:a copy -f flv -y rtmp://127.0.0.1/live/yuankang

播放地址
ffplay rtmp://127.0.0.1/live/yuankang


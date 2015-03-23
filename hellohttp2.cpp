//*****************************************************
// OpenSSL1.0.2以上を使用.
//*****************************************************

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#pragma warning(disable:4996)
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#define SOCKET int
#define SD_BOTH SHUT_WR
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#define READ_BUF_SIZE 4096
#define BUF_SIZE 4097
#define PORT 443
#define BINARY_FRAME_LENGTH 9


// ALPN識別子. h2
static const unsigned char protos[] = { 0x02, 0x68, 0x32 };
static const char cmp_protos[] = { 0x68, 0x32 };
static int protos_len = 3;

//ドラフト14を使う場合
// ALPN識別子. h2-14
//static const uint8_t protos[] = { 0x05, 0x68, 0x32, 0x2d, 0x31, 0x36 };
//static const uint8_t cmp_protos[] = { 0x68, 0x32, 0x2d, 0x31, 0x36 };
//static int protos_len = 6;


#define CLIENT_CONNECTION_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


// 3バイトのネットワークオーダーを4バイト整数へ変換する関数.
char* to_framedata3byte(char *p, int &n);
int get_error();
void close_socket(SOCKET socket, SSL_CTX *_ctx, SSL *_ssl);


int main(int argc, char **argv)
{
    
    //------------------------------------------------------------
    // 接続先ホスト名.
    // HTTP2に対応したホストを指定します.
    //------------------------------------------------------------
    std::string host = "nghttp2.org";
    
    
    //------------------------------------------------------------
    // TCPの準備.
    //------------------------------------------------------------
#ifdef WIN32
    WSADATA	wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 0;
    }
#endif
    
    
    //------------------------------------------------------------
    // SSLの準備.
    //------------------------------------------------------------
    SSL *_ssl;
    SSL_CTX *_ctx;
    
    // SSLライブラリの初期化.
    SSL_library_init();
    
    // エラーを文字列化するための準備.
    SSL_load_error_strings();
    
    // グローバルコンテキスト初期化.
    const SSL_METHOD *meth = SSLv23_method();
    _ctx = SSL_CTX_new(meth);
    
    
    int error = 0;
    struct hostent *hp;
    struct sockaddr_in addr;
    SOCKET _socket;
    
    if (!(hp = gethostbyname(host.c_str()))){
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_addr = *(struct in_addr*)hp->h_addr_list[0];
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    
    if ((_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0){
        return -1;
    }
    if (connect(_socket, (struct sockaddr *)&addr, sizeof(addr))<0){
        return -1;
    }
    
    // sslセッションオブジェクトを作成する.
    _ssl = SSL_new(_ctx);
    
    // ソケットと関連づける.
    SSL_set_fd(_ssl, _socket);
    
    
    
    //------------------------------------------------------------
    // HTTP2の準備.
    //
    // プロトコルのネゴシエーションにALPNという方法を使います。
    // 具体的にはTLSのClientHelleのALPN拡張領域ににこれから使うプロトコル名を記述します.
    // SPDYではNPNという方法が使われましたが、現在のHTTP2仕様ではNPNは廃止されています.
    //
    // protosには文字列ではなくバイナリで、「0x02, 'h','2'」と指定する。
    // 最初の0x02は「h2」の長さを表している.
    //------------------------------------------------------------
    SSL_set_alpn_protos(_ssl, protos, protos_len);
    
    // SSL接続.
    if (SSL_connect(_ssl) <= 0){
        error = get_error();
        ::shutdown(_socket, SD_BOTH);
        close_socket(_socket, _ctx, _ssl);
        return 0;
    }
    
    // 採用されたALPNを確認する.
    const unsigned char  *ret_alpn;
    unsigned int  alpn_len;
    SSL_get0_alpn_selected(_ssl, &ret_alpn, &alpn_len);
    
    if ((int)alpn_len < protos_len - 1){
        error = get_error();
        close_socket(_socket, _ctx, _ssl);
        return 0;
    }
    
    if (memcmp(ret_alpn, cmp_protos, alpn_len) != 0){
        error = get_error();
        close_socket(_socket, _ctx, _ssl);
        return 0;
    }
    
    
    
    //------------------------------------------------------------
    // これからHTTP2通信を開始する合図.
    //------------------------------------------------------------
    int r = 0;
    char buf[BUF_SIZE] = { 0 };
    char* p = buf;
    bool b = false;
    int payload_length = 0;
    int frame_type = 0;
    int ret = 0;
    
    while (1){
        
        r = SSL_write(_ssl, CLIENT_CONNECTION_PREFACE, (int)strlen(CLIENT_CONNECTION_PREFACE));
        ret = SSL_get_error(_ssl, r);
        switch (ret){
            case SSL_ERROR_NONE:
                b = true;
                break;
            case SSL_ERROR_WANT_WRITE:
                continue;
            default:
                if (r == -1){
                    error = get_error();
                    close_socket(_socket, _ctx, _ssl);
                    return 0;
                }
        }
        if (b) break;
    }
    
    
    //------------------------------------------------------------
    // 全てのデータはバイナリフレームで送受信される
    // バイナリフレームは共通の9バイトヘッダと、データ本体であるpayloadを持つ
    //
    // ●ヘッダ部分のフォーマット
    //
    //   1-3バイト目  payloadの長さ。長さにヘッダの9バイトは含まれない。.
    //   4バイト目　フレームのタイプ.
    //   5バイト目　フラグ.
    //   6-9バイト目　ストリームID.
    //
    // [フレームのタイプ]
    //
    // DATA(0x00)  リクエストボディや、レスポンスボディを転送する
    // HEADERS(0x01)  圧縮済みのHTTPヘッダーを転送する
    // PRIORITY(0x02)  ストリームの優先度を変更する
    // RST_STREAM(0x03)  ストリームの終了を通知する
    // SETTINGS(0x04)  接続に関する設定を変更する
    // PUSH_PROMISE(0x05)  サーバーからのリソースのプッシュを通知する
    // PING(0x06)  接続状況を確認する
    // GOAWAY(0x07)  接続の終了を通知する
    // WINDOW_UPDATE(0x08)   フロー制御ウィンドウを更新する
    // CONTINUATION(0x09)  HEADERSフレームやPUSH_PROMISEフレームの続きのデータを転送する
    //------------------------------------------------------------
    
    
    
    //------------------------------------------------------------
    // HTTP2通信のフロー
    //
    // まず最初にSettingフレームを必ず交換します.
    // Settingフレームを交換したら、設定を適用したことを伝えるために必ずACKを送ります.
    //
    // Client -> Server  SettingFrame
    // Client <- Server  SettingFrame
    // Client -> Server  ACK
    // Client <- Server  ACK
    //
    //------------------------------------------------------------
    
    
    
    //------------------------------------------------------------
    // Settingフレームの送信.
    // フレームタイプは「0x04」
    // 全てデフォルト値を採用するためpayloadは空です。
    // SettingフレームのストリームIDは0です.
    //------------------------------------------------------------
    const unsigned char settingframe[BINARY_FRAME_LENGTH] = { 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    while (1){
        
        r = SSL_write(_ssl, settingframe, BINARY_FRAME_LENGTH);
        
        ret = SSL_get_error(_ssl, r);
        switch (ret){
            case SSL_ERROR_NONE:
                b = true;
                break;
            case SSL_ERROR_WANT_WRITE:
                continue;
            default:
                if (r == -1){
                    error = get_error();
                    close_socket(_socket, _ctx, _ssl);
                    return 0;
                }
        }
        if (b) break;
    }
    
    
    //------------------------------------------------------------
    // Settingフレームの受信.
    //------------------------------------------------------------
    memset(buf, 0x00, BUF_SIZE);
    p = buf;
    
    while (1){
        
        r = SSL_read(_ssl, p, READ_BUF_SIZE);
        ret = SSL_get_error(_ssl, r);
        switch (ret){
            case SSL_ERROR_NONE:
                b = true;
                break;
            case SSL_ERROR_WANT_READ:
                continue;
            default:
                if (r == -1){
                    error = get_error();
                    close_socket(_socket, _ctx, _ssl);
                    return 0;
                }
        }
        if (b) break;
    }
    
    
    
    //------------------------------------------------------------
    // ACKの送信.
    // ACKはSettingフレームを受け取った側が送る必要がある.
    // ACKはSettingフレームのフラグに0x01を立ててpayloadを空にしたもの.
    //
    // フレームタイプは「0x04」
    // 5バイト目にフラグ0x01を立てます。
    //------------------------------------------------------------
    const unsigned char settingframeAck[BINARY_FRAME_LENGTH] = { 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00 };
    while (1){
        
        r = SSL_write(_ssl, settingframeAck, BINARY_FRAME_LENGTH);
        
        ret = SSL_get_error(_ssl, r);
        switch (ret){
            case SSL_ERROR_NONE:
                b = true;
                break;
            case SSL_ERROR_WANT_WRITE:
                continue;
            default:
                if (r == -1){
                    error = get_error();
                    close_socket(_socket, _ctx, _ssl);
                    return 0;
                }
        }
        if (b) break;
    }
    
    
    //------------------------------------------------------------
    // HEADERSフレームの送信.
    //
    // フレームタイプは「0x01」
    // このフレームに必要なヘッダがすべて含まれていてこれでストリームを終わらせることを示すために、
    // END_STREAM(0x1)とEND_HEADERS(0x4)を有効にします。
    // 具体的には5バイト目のフラグに「0x05」を立てます。
    // ストリームIDは「0x01」を使います.
    //
    // ここまででヘッダフレームは「ペイロードの長さ(3バイト), 0x01, 0x05, 0x00, 0x00, 0x00, 0x01」になります.
    //
    //
    // ●HTTP1.1でのセマンティクス
    // 　　"GET / HTTP1/1"
    // 　　"Host: nghttp2.org
    //
    // ●HTTP2でのセマンティクス
    //		:method GET
    //		:path /
    //		:scheme https
    //		:authority nghttp2.org
    //
    // 本来HTTP2はHPACKという方法で圧縮します.
    // 今回は上記のHTTP2のセマンティクスを圧縮なしで記述します.
    //
    // 一つのヘッダフィールドの記述例
    //
    // |0|0|0|0|      0|   // 最初の4ビットは圧縮に関する情報、次の4ビットはヘッダテーブルのインデクス.(今回は圧縮しないのですべて0)
    // |0|            7|   // 最初の1ビットは圧縮に関する情報(今回は0)、次はフィールドの長さ
    // |:method|           // フィールドをそのままASCIIのオクテットで書く。
    // |0|            3|   // 最初の1ビットは圧縮に関する情報(今回は0)、次はフィールドの長さ
    // |GET|               // 値をそのままASCIIのオクテットで書く。
    //
    // 上記が一つのヘッダフィールドの記述例で、ヘッダーフィールドの数だけこれを繰り返す.
    //
    //------------------------------------------------------------
    const unsigned char headersframe[70] = {
        0x00, 0x00, 0x3d, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01,	// ヘッダフレーム
        0x00,													// 圧縮情報
        0x07, 0x3a, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64,			// 7 :method
        0x03, 0x47, 0x45, 0x54,									// 3 GET
        0x00,													// 圧縮情報
        0x05, 0x3a, 0x70, 0x61, 0x74, 0x68,						// 5 :path
        0x01, 0x2f,												// 1 /
        0x00,													// 圧縮情報
        0x07, 0x3a, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x65,			// 7 :scheme
        0x05, 0x68, 0x74, 0x74, 0x70, 0x73,						// 5 https
        0x00,													// 圧縮情報
        0x0a, 0x3a, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79,			// 10 :authority
        0x0b, 0x6e, 0x67, 0x68, 0x74, 0x74, 0x70, 0x32, 0x2e, 0x6f, 0x72, 0x67 };	// 11 nghttp2.org
    
    while (1){
        
        r = SSL_write(_ssl, headersframe, 70);
        
        ret = SSL_get_error(_ssl, r);
        switch (ret){
            case SSL_ERROR_NONE:
                b = true;
                break;
            case SSL_ERROR_WANT_WRITE:
                continue;
            default:
                if (r == -1){
                    error = get_error();
                    close_socket(_socket, _ctx, _ssl);
                    return 0;
                }
        }
        if (b) break;
    }
    
    
    
    
    //------------------------------------------------------------
    // HEADERSフレームの受信.
    //------------------------------------------------------------
    
    // まずはヘッダフレームを受信してpayloadのlengthを取得する。
    while (1){
        
        memset(buf, 0x00, BINARY_FRAME_LENGTH);
        p = buf;
        
        while (1){
            
            r = SSL_read(_ssl, p, BINARY_FRAME_LENGTH);
            ret = SSL_get_error(_ssl, r);
            switch (ret){
                case SSL_ERROR_NONE:
                    b = true;
                    break;
                case SSL_ERROR_WANT_READ:
                    continue;
                default:
                    if (r == -1){
                        error = get_error();
                        close_socket(_socket, _ctx, _ssl);
                        return 0;
                    }
            }
            if (b) break;
        }
        
        if (r == 0) continue;
        
        // ACKが返ってくる場合があるのでACKなら無視して次を読む。
        if (memcmp(buf, settingframeAck, BINARY_FRAME_LENGTH) == 0){
            continue;
        }
        else{
            
            // payloadの長さを取得する。
            p = to_framedata3byte(p, payload_length);
            
            // フレームタイプがHEADERS_FRAMEではなかったら読み飛ばす。
            memcpy(&frame_type, p, 1);
            if (frame_type != 1){
                
                while (payload_length > 0){
                    
                    r = SSL_read(_ssl, p, payload_length);
                    ret = SSL_get_error(_ssl, r);
                    switch (ret){
                        case SSL_ERROR_NONE:
                            b = true;
                            break;
                        case SSL_ERROR_WANT_READ:
                            continue;
                        default:
                            if (r == -1){
                                error = get_error();
                                close_socket(_socket, _ctx, _ssl);
                                return 0;
                            }
                    }
                    payload_length -= r;
                }
                continue;
            }
            break;
        }
    }
    
    
    //------------------------------------------------------------
    // HEADERSフレームのpayloadの受信.
    //------------------------------------------------------------
    while (payload_length > 0){
        
        memset(buf, 0x00, BUF_SIZE);
        p = buf;
        
        r = SSL_read(_ssl, p, payload_length);
        ret = SSL_get_error(_ssl, r);
        switch (ret){
            case SSL_ERROR_NONE:
                break;
            case SSL_ERROR_WANT_READ:
                continue;
            default:
                if (r == -1){
                    error = get_error();
                    close_socket(_socket, _ctx, _ssl);
                    return 0;
                }
        }
        payload_length -= r;
    }
    
    
    //------------------------------------------------------------
    // DATAフレームの受信.
    //------------------------------------------------------------
    
    // まずはヘッダフレームを受信してpayloadのlengthを取得する。
    while (1){
        
        memset(buf, 0x00, BUF_SIZE);
        p = buf;
        
        r = SSL_read(_ssl, p, BINARY_FRAME_LENGTH);
        ret = SSL_get_error(_ssl, r);
        switch (ret){
            case SSL_ERROR_NONE:
                break;
            case SSL_ERROR_WANT_READ:
                continue;
            default:
                if (r == -1){
                    error = get_error();
                    close_socket(_socket, _ctx, _ssl);
                    return 0;
                }
        }
        if (b) break;
    }
    
    to_framedata3byte(p, payload_length);
    
    // 次にpayloadを受信する。
    while (payload_length > 0){
        
        memset(buf, 0x00, BUF_SIZE);
        p = buf;
        
        r = SSL_read(_ssl, p, READ_BUF_SIZE);
        ret = SSL_get_error(_ssl, r);
        switch (ret){
            case SSL_ERROR_NONE:
                break;
            case SSL_ERROR_WANT_READ:
                continue;
            default:
                if (r == -1){
                    error = get_error();
                    close_socket(_socket, _ctx, _ssl);
                    return 0;
                }
        }
        
        payload_length -= r;
        
        printf("%s", p);
    }
    
    
    //------------------------------------------------------------
    // GOAWAYの送信.
    //
    // これ以上データを送受信しない場合はGOAWAYフレームを送信します.
    // フレームタイプは「0x07」
    // ストリームIDは「0x01」
    //------------------------------------------------------------
    const char goawayframe[17] = { 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    
    while (1){
        
        r = SSL_write(_ssl, goawayframe, 17);
        
        ret = SSL_get_error(_ssl, r);
        switch (ret){
            case SSL_ERROR_NONE:
                b = true;
                break;
            case SSL_ERROR_WANT_WRITE:
                continue;
            default:
                if (r == -1){
                    error = get_error();
                    close_socket(_socket, _ctx, _ssl);
                    return 0;
                }
        }
        if (b) break;
    }
    
    
    
    //------------------------------------------------------------
    // 後始末.
    //------------------------------------------------------------
    close_socket(_socket, _ctx, _ssl);
    
    
    return 0;
    
}

void close_socket(SOCKET socket, SSL_CTX *_ctx, SSL *_ssl){
    
    // SSL/TLS接続をシャットダウンする。
    SSL_shutdown(_ssl);
    SSL_free(_ssl);
    
    ::shutdown(socket, SD_BOTH);
    
#ifdef WIN32
    ::closesocket(socket);
    WSACleanup();
#else
    ::close(socket);
#endif
    
    SSL_CTX_free(_ctx);
    ERR_free_strings();
    
}

int get_error(){
#ifdef WIN32
    return WSAGetLastError();
#endif
    return errno;
}

char* to_framedata3byte(char *p, int &n){
    u_char buf[4] = { 0 };
    memcpy(&(buf[1]), p, 3);
    memcpy(&n, buf, 4);
    n = ntohl(n);
    p += 3;
    return p;
}


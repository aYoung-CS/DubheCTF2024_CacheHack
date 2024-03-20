files=("a.patch" "b.patch" "libevent-2.1.12-stable.tar.gz" "memcached-1.6.24.tar.gz")

for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        :
    else
        echo "$file does not exist"
        exit
    fi
done
tar -zxvf libevent-2.1.12-stable.tar.gz
tar -zxvf memcached-1.6.24.tar.gz
cd libevent-2.1.12-stable
./configure --prefix=/tmp/libevent
make && make install
cd - >/dev/null
patch memcached-1.6.24/proto_bin.c < a.patch
patch memcached-1.6.24/items.c < b.patch
cd memcached-1.6.24
CFLAGS="-g -O0" ./configure --with-libevent=/tmp/libevent
make
echo -e "\nDone"
# gcc -I . -fPIC -c -o libserver.a src/server_glue.c

main: clean libfirewall.a libserver.a libexternalfirewall.a
	gcc src/main.c libfirewall.a libexternalfirewall.a -lpthread -ldl -o main

test: clean libfirewall.a libserver.a
	gcc src/test.c libserver.a libfirewall.a -lpthread -ldl -o main

libserver.a:
	gcc -fPIC src/server_glue.c -c -o libserver.a

libexternalfirewall.a:
	gcc -fPIC src/external_firewall.c -c -o libexternalfirewall.a

libfirewall.a: src/lib.rs
	cargo build # because somebody has to compile the external crates
	rustc --crate-type=staticlib -L target/debug/deps src/lib.rs -o libfirewall.a

clean:
	rm -f main libfirewall.a libserver.a libexternalfirewall.a

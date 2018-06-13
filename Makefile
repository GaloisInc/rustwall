# gcc -I . -fPIC -c -o libserver.a src/server_glue.c

main: clean libfirewall.a libserver.a libexternalfirewall.a
	gcc src/main.c libfirewall.a libserver.a libexternalfirewall.a -lpthread -ldl -o main

test: clean libfirewall.a libexternalfirewall.a
	gcc src/test.c libfirewall.a libexternalfirewall.a -lpthread -ldl -o test

libserver.a:
	gcc -fPIC src/server_glue.c -c -o libserver.a

libexternalfirewall.a:
	gcc -fPIC src/external_firewall.c -c -o libexternalfirewall.a

libfirewall.a: src/lib.rs
	cargo build # because somebody has to compile the external crates. This wont help with the features unfortunately
	rustc --crate-type=staticlib -L target/debug/deps src/lib.rs -o libfirewall.a -g

clean:
	rm -f main libfirewall.a libserver.a libexternalfirewall.a

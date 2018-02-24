main: clean libsample.a
	gcc src/main.c libsample.a -lpthread -ldl -o main

libsample.a: src/lib.rs
	cargo build # because somebody has to compile the external crates
	rustc --crate-type=staticlib -L target/debug/deps src/lib.rs -o libsample.a

clean:
	rm -f main libsample.a

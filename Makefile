main: libsample.a
	gcc src/main.c libsample.a -lpthread -ldl -o main

libsample.a: src/lib.rs
	rustc --crate-type=staticlib src/lib.rs -o libsample.a

clean:
	rm -f main libsample.a

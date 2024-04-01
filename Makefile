all:
	gcc -o apager apager.c -static -g
	gcc -o dpager dpager.c -static -g
	gcc -o hello_world hello_world.c -static -T ld_custom -g
	gcc -o null null.c -static -T ld_custom -g

clean:
	rm apager
	rm dpager
	rm hello_world
	rm null
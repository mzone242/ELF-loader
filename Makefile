all:
	gcc -o apager apager.c -static -g -static-libgcc -Wl,-z,norelro
	gcc -o dpager dpager.c -static -g -static-libgcc -Wl,-z,norelro
	gcc -o hpager hpager.c -static -g -static-libgcc -Wl,-z,norelro
	gcc -o hello_world hello_world.c -static -T ld_custom -g -static-libgcc -Wl,-z,norelro
	gcc -o null null.c -static -T ld_custom -g -static-libgcc -Wl,-z,norelro 
	gcc -o malloc malloc.c -static -T ld_custom -g -static-libgcc -Wl,-z,norelro

clean:
	rm apager
	rm dpager
	rm hpager
	rm hello_world
	rm null
	rm malloc
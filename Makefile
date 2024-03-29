apager:
	gcc -o apager apager.c -static

hello_world:
	gcc -o hello_world hello_world.c -static -T ld_custom

clean:
	rm apager
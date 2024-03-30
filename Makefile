apager:
	gcc -o apager apager.c -static -g
	
hello_world:
	gcc -o hello_world hello_world.c -static -T ld_custom -g

clean:
	rm apager
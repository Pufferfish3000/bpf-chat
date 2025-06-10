.PHONY: build format lint build-deps clean

build:
	cmake -S . -B ./build
	cmake --build ./build	

format:
	find . -type f \( -iname "*.c" -o -iname "*.h" \) | xargs clang-format -style=file -i

lint: build
	@CodeChecker analyze ./build/compile_commands.json --enable sensitive --output ./codechecker
	-CodeChecker parse --export html --output ./codechecker/report ./codechecker
	firefox ./codechecker/report/index.html &

clean:
	rm -rf ./bin
	rm -rf ./build
	rm -rf ./codechecker

build-deps:
	pip install -r requirements.txt

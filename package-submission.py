import zipfile
import sys
import pathlib
import os


def main(args):
	if len(args) < 2:
		usage(sys.stderr)
		return 1

	project_name = args[1]
	extra_files = list(map(pathlib.Path, args[2:]))

	cwd = pathlib.Path('.')
	build_dir = cwd / 'build'

	if not build_dir.exists():
		sys.stderr.write('Build directory is missing, please build your project first')
		return 1

	bin_files = [
		build_dir / f'{project_name}.bin',
		build_dir / 'bootloader' / 'bootloader.bin',
		build_dir / 'partition_table' / 'partition-table.bin'
	]

	missing = list(filter(lambda p: not p.exists(), bin_files))

	if len(missing) != 0:
		sys.stderr.write(f'Missing bin files: {missing}\n')
		return 2

	src_files = [
		cwd / 'CMakeLists.txt',
		cwd / 'sdkconfig',
		cwd / 'components',
		cwd / 'main'
	]
	missing = list(filter(lambda p: not p.exists(), src_files))

	if len(missing) != 0:
		sys.stderr.write(f'Missing source files: {missing}\n')
		return 2

	missing = list(filter(lambda p: not p.exists(), extra_files))

	if len(missing) != 0:
		sys.stderr.write(f'Missing files: {missing}\n')
		return 3

	with zipfile.ZipFile(f'{project_name}.zip', 'w') as archive:
		archive.mkdir('bin')

		for f in bin_files:
			archive.write(f.resolve(), f'bin/{f.name}')

		archive.mkdir('src')

		for f in filter(lambda p: not p.is_dir(), src_files):
			archive.write(f.resolve(), f'src/{f.name}')

		for d in filter(lambda p: p.is_dir(), src_files):
			for (dirpath, dirnames, filenames) in os.walk(d.resolve(), topdown=True):
				dirpath = pathlib.Path(dirpath).relative_to(cwd.resolve())

				archive_path = f"src/{dirpath}"
				archive.mkdir(archive_path)
				for f in filter(
					lambda p: p.suffix in ['.txt', '.c', '.h'],
					map(pathlib.Path, filenames)
				):
					archive.write(
						(dirpath / f).resolve(),
						f'src/{archive_path}/{f}'
					)

		if extra_files != []:
			archive.mkdir('extra')
			for f in extra_files:
				archive.write(f.resolve(), f'extra/{f}')

	return 0


def usage(out=sys.stdout):
	out.write("Usage: package-submission.py PROJECT-NAME [EXTRA_FILES...]\n")


if __name__ == '__main__':
	sys.exit(main(sys.argv))

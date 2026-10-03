import tarfile


def extract_archive(archive_path, dest_dir):
    with tarfile.open(archive_path) as tf:
        tf.extractall(dest_dir)

def run_backup(user_supplied_path)
  system("tar -czf backup.tar.gz " + user_supplied_path)
end

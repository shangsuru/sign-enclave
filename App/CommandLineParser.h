#pragma once

#include <string>
#include <iostream>

enum Command
{
  START,
  ERROR,
  SIGN,
  VERIFY
};

struct CommandLineArguments
{
  char *message;
  std::string signature;
  char *export_keyfile;
  char *import_keyfile;
  Command command;
};

const std::string usage = "usage: %s [-e file_name] [-i sealed_keyfile] [-m message_to_sign] [-p message_to_verify -s signature]\n";

CommandLineArguments getArgs(int nargc, char **nargv);
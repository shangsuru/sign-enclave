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
  char *signature_file;
  Command command;
};

const std::string usage = "usage: %s [-m message_to_sign] [-p message_to_verify -s signature_file]\n";

CommandLineArguments getArgs(int nargc, char **nargv);
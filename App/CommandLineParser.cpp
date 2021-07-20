#include "CommandLineParser.h"

CommandLineArguments getArgs(int nargc, char **nargv)
{
  CommandLineArguments args = {"", "", START};

  for (int i = 0; i < nargc; i++)
  {
    if (nargv[i][0] == '-' && i < nargc - 1)
    {
      switch (nargv[i][1])
      {
      case 'm': // message to sign
        if (args.command != START)
          goto error;

        args.message = nargv[++i];
        args.command = SIGN;
        break;
      case 'p': // message to verify
        if (args.command != START && args.command != VERIFY)
          goto error;

        args.message = nargv[++i];
        args.command = VERIFY;
        break;
      case 's': // signature of the message
        if (args.command != START && args.command != VERIFY)
          goto error;

        args.signature_file = nargv[++i];
        args.command = VERIFY;
        break;
      default:
        goto error; // Unknown command line option
      }
    }
  }

  if (args.command == START || (args.command == VERIFY && (args.message == "" || args.signature_file == "")))
    goto error; // Missing arguments

  return args;

error:
  std::cout << usage << std::endl;
  args.command = ERROR;
  return args;
}
#include "CommandLineParser.h"

CommandLineArguments getArgs(int nargc, char **nargv)
{
  CommandLineArguments args = {NULL, "", NULL, NULL, START};

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

        args.signature.assign(nargv[++i]);
        args.command = VERIFY;
        break;
      case 'e': // name of the file to export generated key pair to
        args.export_keyfile = nargv[++i];
        break;
      case 'i': // name of the keyfile to import
        args.import_keyfile = nargv[++i];
        break;
      default:
        goto error; // Unknown command line option
      }
    }
  }

  if (args.command == START || (args.command == VERIFY && (args.message == NULL || args.signature == "")))
    goto error; // Missing arguments

  return args;

error:
  std::cout << usage << std::endl;
  args.command = ERROR;
  return args;
}
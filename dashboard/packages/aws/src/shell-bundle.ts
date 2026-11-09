import "server-only";

import { shellExec, shellList, shellMkdir, shellRead, shellRemove, shellWrite } from "./shell-actions";

/** The server actions the console's Terminal and FileExplorer take. */
export const SHELL_ACTIONS = {
  exec: shellExec,
  list: shellList,
  read: shellRead,
  write: shellWrite,
  remove: shellRemove,
  mkdir: shellMkdir,
};

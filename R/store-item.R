#' @title Store a credential item
#' 
#' @description In order to store credential items, OS resources (such as the
#'              Mac OS Keychain) are used when possible. As a fall-back option,
#'              a file-based storage option is available which encrypts
#'              sensitive information and saves the key to the user's
#'              .Rprofile.
#'
#' @param item  A credential item to be stored.
#' @param vault A string indicating how to store the credential
#'
#' @return NULL (invisibly).
#' 
#' @export
storeItem <- function(item, vault) {
  UseMethod("storeItem", item)
}
#' @export
storeItem.LoginItem <- function(item, vault = defaultStorageMode()) {
  storeLoginItemFileBased <- function(x) {
    fileBasedStorageSession()
    secretr_path <- getOption("secretr.path")
    if (file.exists(secretr_path)) {
      vault <- readRDS(secretr_path)
      if (getItemId(x) %in% sapply(vault, getItemId)) {
        stop("the item to be stored is already present.")
        return(invisible(NULL))
      } else if (length(vault) == 0) {
        vault <- list(encryptItem(x))
      } else {
        vault[[length(vault) + 1]] <- encryptItem(x)
      }
    } else {
      vault <- list(encryptItem(x))
    }
    saveRDS(vault, secretr_path)
    return(invisible(NULL))
  }
  storeLoginItemKeychain <- function(x) {
    .Call("storeLoginItemKeychain_", x$service, x$username, x$password)
    return(invisible(NULL))
  }

  if (vault == "keychain") {
    return(storeLoginItemKeychain(item))
  } else if (vault == "file") {
    return(storeLoginItemFileBased(item))
  } else stop("unknown vault option")
}
#' @export
storeItem.default <- function(item, vault) {
  stop("function not implemented for objects of class ",
       paste(class(item), collapse = ", "))
}

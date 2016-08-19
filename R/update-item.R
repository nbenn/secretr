#' @title Update a credential item
#' 
#' @description In case an already existing credential item changes, this
#'              function may be used to modify its stored representation.
#'
#' @param item  A credential item to be modified.
#' @param vault A string indicating how the credential to be modified is
#'              stored.
#'
#' @return NULL (invisibly).
#' 
#' @export
updateItem <- function(item, vault) {
  UseMethod("updateItem", item)
}
#' @export
updateItem.LoginItem <- function(item, vault = defaultStorageMode()) {
  updateLoginItemFileBased <- function(x) {
    fileBasedStorageSession()
    secretr_path <- getOption("secretr.path")
    if (!file.exists(secretr_path)) {
      stop("cannot find .Rsecrets file.")
    }
    vault <- readRDS(secretr_path)
    index <- grep(getItemId(x), sapply(vault, getItemId), fixed = TRUE)
    if (length(index) != 1) {
      stop("did not find 1, but ", length(index), " matches")
    }
    vault[[index]] <- encryptItem(x)
    saveRDS(vault, secretr_path)
    return(invisible(NULL))
  }
  updateLoginItemKeychain <- function(x) {
    res <- .Call("updateLoginItemKeychain_", x$service, x$username, x$password)
    return(invisible(res))
  }
  if (vault == "keychain") return(updateLoginItemKeychain(item))
  else if (vault == "file") return(updateLoginItemFileBased(item))
  else stop("unknown vault option")
}
#' @export
updateItem.default <- function(item, vault) {
  stop("function not implemented for objects of class ",
       paste(class(item), collapse = ", "))
}

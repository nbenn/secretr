#' @title Delete a credential item
#' 
#' @description Remove a credential item from secure storage.
#'
#' @param id    The ID of the credential item to be deleted.
#' @param vault A string indicating where the requested credential is stored.
#'
#' @return NULL (invisibly).
#' 
#' @export
removeItem <- function(id, vault = defaultStorageMode()) {
  removeLoginItemFileBased <- function(x) {
    fileBasedStorageSession()
    secretr_path <- getOption("secretr.path")
    if (!file.exists(secretr_path)) {
      stop("cannot find .Rsecrets file.")
    }
    vault <- readRDS(secretr_path)
    index <- grep(x, sapply(vault, getItemId), fixed = TRUE)
    if (length(index) != 1) {
      stop("did not find 1, but ", length(index), " matches")
    }
    saveRDS(vault[-index], secretr_path)
    return(invisible(NULL))
  }
  removeLoginItemKeychain <- function(x) {
    return(invisible(.Call("removeLoginItemKeychain_", x)))
  }
  if (vault == "keychain") return(removeLoginItemKeychain(id))
  else if (vault == "file") return(removeLoginItemFileBased(id))
  else stop("unknown vault option")
}

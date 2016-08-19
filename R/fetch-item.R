#' @title Fetch a credential item
#' 
#' @description Fetches a credential item from secure storage.
#'
#' @param id    The ID of the requested credential item.
#' @param vault A string indicating where the requested credential is stored.
#'
#' @return The requested credential item.
#' 
#' @export
fetchItem <- function(id, vault = defaultStorageMode()) {
  fetchLoginItemFileBased <- function(x) {
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
    return(decryptItem(vault[[index]]))
  }
  fetchLoginItemKeychain <- function(x) {
    result <- .Call("fetchLoginItemKeychain_", x)
    return(LoginItem(x, result$username, result$password))
  }
  if (vault == "keychain") return(fetchLoginItemKeychain(id))
  else if (vault == "file") return(fetchLoginItemFileBased(id))
  else stop("unknown vault option")
}

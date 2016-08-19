context("FileBasedStorage")

options(secretr.key  = generatePassword(length = 32, symbols = FALSE),
        secretr.path = file.path(tempdir(), ".Rsecrets"))

test_that("en- and decryption works", {
  cred1 <- LoginItem(service = "test service", username = "testuser",
                     password = generatePassword(length = 15))
  cred2 <- LoginItem(service = "test service", username = "testuser",
                     password = generatePassword(length = 16))
  cred3 <- LoginItem(service = "test service", username = "testuser",
                     password = generatePassword(length = 17))

  expect_equal(decryptItem(encryptItem(cred1)), cred1)
  expect_equal(decryptItem(encryptItem(cred2)), cred2)
  expect_equal(decryptItem(encryptItem(cred3)), cred3)
})

test_that("file-based storage works", {
  cred1 <- LoginItem(service = "test service", username = "testuser")
  cred2 <- LoginItem(service = "test service", username = "testuser")
  cred3 <- LoginItem(service = "test service 2", username = "testuser")
  storeItem(cred1, vault = "file")

  expect_equal(fetchItem(getItemId(cred1), vault = "file"), cred1)
  expect_error(storeItem(cred2, vault = "file"),
               paste0("the item to be stored is already present."),
               fixed = TRUE)
  expect_equal(updateItem(cred2, vault = "file"), NULL)
  expect_equal(fetchItem("test service", vault = "file"), cred2)
  expect_error(updateItem(cred3, vault = "file"),
               paste0("did not find 1, but 0 matches"),
               fixed = TRUE)
  expect_equal(storeItem(cred3, vault = "file"), NULL)
  expect_equal(length(readRDS(getOption("secretr.path"))), 2)
  expect_error(fetchItem("test service 3", vault = "file"),
               paste0("did not find 1, but 0 matches"), fixed = TRUE)
  expect_error(removeItem("test service 3", vault = "file"),
               paste0("did not find 1, but 0 matches"), fixed = TRUE)
  expect_equal(removeItem("test service 2", vault = "file"), NULL)
  expect_equal(removeItem(getItemId(cred1), vault = "file"), NULL)
  expect_equal(length(readRDS(getOption("secretr.path"))), 0)
})

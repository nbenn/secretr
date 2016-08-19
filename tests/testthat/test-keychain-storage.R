context("DefaultStorage")

test_that("default storage works", {
  cred1 <- LoginItem(service = "test service", username = "testuser")
  cred2 <- LoginItem(service = "test service", username = "testuser")
  cred3 <- LoginItem(service = "test service 2", username = "testuser")
  storeItem(cred1)

  expect_equal(fetchItem(getItemId(cred1)), cred1)
  expect_error(storeItem(cred2),
               paste0("The item to be stored is already present."),
               fixed = TRUE)
  expect_equal(updateItem(cred2), NULL)
  expect_equal(fetchItem("test service"), cred2)
  expect_error(updateItem(cred3),
               paste0("Did not find 1, but 0 matches."),
               fixed = TRUE)
  expect_equal(storeItem(cred3), NULL)
  expect_error(fetchItem("test service 3"),
               paste0("Did not find 1, but 0 matches."), fixed = TRUE)
  expect_error(removeItem("test service 3"),
               paste0("Did not find 1, but 0 matches."), fixed = TRUE)
  expect_equal(removeItem("test service 2"), NULL)
  expect_equal(removeItem(getItemId(cred1)), NULL)
})

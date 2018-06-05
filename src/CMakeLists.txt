include_directories(.)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic -Wextra")

add_executable(
  main

  intkey-circuit-gl1.cpp
)

target_link_libraries(
  main

  snark
)

target_include_directories(
  main

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

add_executable(
  test-gl2 

  test-gadgetlib2.cpp
)

target_link_libraries(
  test-gl2

  snark
)

target_include_directories(
  test-gl2

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

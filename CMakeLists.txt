project (win32ClientServer)

set(sources
    main.cpp)

source_group("Sources" FILES ${sources})


add_executable(${PROJECT_NAME} ${sources} )
target_compile_definitions(${PROJECT_NAME} PRIVATE WIN32_LEAN_AND_MEAN)
#set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/level='requireAdministrator' /uiAccess='false'")
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'")

#target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../ThirdParty/stb) # to access stb
#target_link_libraries (${PROJECT_NAME} PRIVATE glfw volk meshoptimizer)
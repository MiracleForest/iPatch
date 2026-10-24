add_rules("mode.debug", "mode.release")
set_encodings("utf-8")

add_repositories("miracleforest-repo https://github.com/MiracleForest/xmake-repo.git")

add_requires("xbyak v7.44")

target("ipatch")
    set_kind("$(kind)")
    add_files("src/*.cpp")
    set_languages("c++23")
    add_includedirs("include")
    add_packages("xbyak")
    add_headerfiles("include/(ipatch/*.hpp)")
    add_links("psapi")

    add_defines(
        "NOMINMAX",
        "UNICODE",
        "WIN32_LEAN_AND_MEAN",
        "_WIN32_WINNT=0x0A00"
    )

    if is_plat("mingw") or is_plat("msys") then
        add_cxflags("-Wall", "-Wextra", "-Wpedantic", { force = true } )
    else
        add_cxflags("/utf-8", "/EHsc", "/W4", "/wd4251")
        if get_config("toolchain") == "msvc" then
            add_cxflags("/permissive-", "/Zc:__cplusplus")
        end
    end

    if is_kind("shared") then
        add_defines("IPATCH_SHARED")
        add_defines("IPATCH_BUILDING")
    end

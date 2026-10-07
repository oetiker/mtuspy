# Homebrew formula for mtuspy. This repository is its own tap:
#
#   brew tap oetiker/mtuspy https://github.com/oetiker/mtuspy
#   brew install mtuspy
#
# The version and the four sha256 lines are rewritten by
# .github/workflows/release-build-local.yml after the release artifacts exist. The
# trailing marker comments are what that rewrite matches on: do not remove them.
# The values below are placeholders until the first release built by that workflow.
class Mtuspy < Formula
  desc "Path MTU discovery tool using native ICMP with Don't Fragment bit"
  homepage "https://github.com/oetiker/mtuspy"
  version "0.1.3"
  license "MIT"

  # Without a bottle, Homebrew treats this formula as a source build and refuses to
  # install on a Mac whose Command Line Tools are older than its macOS, although
  # nothing here is compiled. The block is rewritten by
  # .github/workflows/release-build-local.yml once a release's bottles exist, and
  # the marker comments are the range that rewrite replaces: do not remove them.
  #
  # One bottle per architecture is enough: on macOS, Homebrew falls back to a bottle
  # built for an older macOS of the same architecture, so the bottles are built on
  # the oldest runner image available for each architecture.
  # BOTTLE-START
  # BOTTLE-END

  on_macos do
    on_arm do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # mac-arm
    end
    on_intel do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # mac-x86
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # linux-x86
    end
    on_arm do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-aarch64-unknown-linux-musl.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # linux-arm
    end
  end

  def install
    bin.install "mtuspy"
    man1.install "man/mtuspy.1"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/mtuspy --version")
  end
end

# Homebrew formula for mtuspy. This repository is its own tap.
#
# The release build rewrites the version line, the four sha256 lines by their
# marker comments and the bottle block between the BOTTLE markers. Keep the
# markers, and keep each url line directly above its sha256 line.
class Mtuspy < Formula
  desc "Path MTU discovery tool using native ICMP with Don't Fragment bit"
  homepage "https://github.com/oetiker/mtuspy"
  version "0.2.0"
  license "MIT"

  # BOTTLE-START
  bottle do
    root_url "https://github.com/oetiker/mtuspy/releases/download/v0.2.0"
    sha256 cellar: :any_skip_relocation, arm64_sonoma: "7c7311a4889676b035943658893fedbc55a9e68fbcf44f707cfae5ece287b3b3"
  end
  # BOTTLE-END

  on_macos do
    on_arm do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "0677eca41ee1c5de0341652b3024789d5a15eb51e14f8b7a6eaabe1cc275ccce" # mac-arm
    end
    on_intel do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "5a78284e6b6cc36bc24f23f62b9d848b5652c523c7e5289b8677c1e35339e641" # mac-x86
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "39a58bc00b609ffc85d8a020a93fd1f56e2aaaa04f8c565bbf189ac9d62c597b" # linux-x86
    end
    on_arm do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-aarch64-unknown-linux-musl.tar.gz"
      sha256 "9dfc45b5b4b5bacd9f1aee8cef00d7dc27811b31fe72742ab1624817ddc12e95" # linux-arm
    end
  end

  def install
    bin.install "mtuspy"
    Dir["man/*.[1-9]"].each { |page| (man/"man#{page[-1]}").install page }
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/mtuspy --version")
  end
end

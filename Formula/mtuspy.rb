# Homebrew formula for mtuspy. This repository is its own tap.
#
# The release build rewrites the version line, the four sha256 lines by their
# marker comments and the bottle block between the BOTTLE markers. Keep the
# markers, and keep each url line directly above its sha256 line.
class Mtuspy < Formula
  desc "Path MTU discovery tool using native ICMP with Don't Fragment bit"
  homepage "https://github.com/oetiker/mtuspy"
  version "0.2.2"
  license "MIT"

  # BOTTLE-START
  bottle do
    root_url "https://github.com/oetiker/mtuspy/releases/download/v0.2.2"
    sha256 cellar: :any_skip_relocation, arm64_sonoma: "1281ddfc476a535aba8b2f5ec87df4334a286a7fd6aa90917b8dabee9c4e56e5"
  end
  # BOTTLE-END

  on_macos do
    on_arm do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "5b25a38070ea3d7efe80949ccbe7521d3befa5787249144ce97902a5723ab51f" # mac-arm
    end
    on_intel do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "e2c8a577061979dbb054dd20c7a3f8b690bda0dcd1b916f060bdafdcc0f8312c" # mac-x86
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "706c98ab17602dd4284913919c133c6ef682244b3f447391021fda4be3ee2ea8" # linux-x86
    end
    on_arm do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-aarch64-unknown-linux-musl.tar.gz"
      sha256 "aedf54aa33196767cb589f2494b7b891537cd5b5eb1b6405f7dd1e28eaa4de24" # linux-arm
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

# Homebrew formula for mtuspy. This repository is its own tap.
#
# The release build rewrites the version line, the four sha256 lines by their
# marker comments and the bottle block between the BOTTLE markers. Keep the
# markers, and keep each url line directly above its sha256 line.
class Mtuspy < Formula
  desc "Path MTU discovery tool using native ICMP with Don't Fragment bit"
  homepage "https://github.com/oetiker/mtuspy"
  version "0.2.3"
  license "MIT"

  # BOTTLE-START
  bottle do
    root_url "https://github.com/oetiker/mtuspy/releases/download/v0.2.3"
    sha256 cellar: :any_skip_relocation, arm64_big_sur: "1fb822de23e0cb397fd42a1ccb137f6ecd804f145844d5aa02f131bf9fff92c1"
  end
  # BOTTLE-END

  on_macos do
    on_arm do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "bc3c917a4d04192425a9ee734528e02e342c40a77a661656b9ab462c68ea19fa" # mac-arm
    end
    on_intel do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "0b2d9028f9fbca8600baf637aad96343c0ac0e591f55b8b00127c3f6d0a520c4" # mac-x86
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "00eb09d71b5eade98815078aeedb3c568afc32291ca6fd8307ac9dfaf88e7944" # linux-x86
    end
    on_arm do
      url "https://github.com/oetiker/mtuspy/releases/download/v#{version}/mtuspy-#{version}-aarch64-unknown-linux-musl.tar.gz"
      sha256 "d57e2d220c96665c71b61abe3627b15ac47473e08ba29361d1b0dc36e89cda0e" # linux-arm
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

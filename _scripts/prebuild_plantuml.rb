# _scripts/prebuild_plantuml.rb
# 构建前扫描所有 PlantUML 代码块，渲染为 SVG 存到 assets/plantuml/
# 用法: ruby _scripts/prebuild_plantuml.rb

require "digest"
require "fileutils"
require "open3"
require "net/http"
require "uri"
require "zlib"

OUT = File.join(__dir__, "..", "assets", "plantuml")
POSTS = File.join(__dir__, "..", "_posts")

# 查找 plantuml jar 路径
def find_jar
  candidates = [
    File.join(__dir__, "..", "plantuml.jar"),           # 项目根目录
    "/usr/share/plantuml/plantuml.jar",                 # apt install plantuml
  ]
  candidates.each { |p| return p if File.exist?(p) }
  nil
end

JAR = find_jar

def encode6bit(b)
  if b < 10 then (48 + b).chr
  elsif b < 36 then (65 + b - 10).chr
  elsif b < 62 then (97 + b - 36).chr
  elsif b == 62 then "-"
  elsif b == 63 then "_"
  else "?"
  end
end

def encode64(data)
  r = ""
  data.each_slice(3) do |s|
    b1, b2, b3 = s[0], s[1] || 0, s[2] || 0
    r << encode6bit(b1 >> 2)
    r << encode6bit(((b1 & 0x3) << 4) | (b2 >> 4))
    r << encode6bit(((b2 & 0xF) << 2) | (b3 >> 6))
    r << encode6bit(b3 & 0x3F)
  end
  r
end

def render_jar(jar, src, out)
  stdout, stderr, status = Open3.capture3(
    "java", "-Djava.awt.headless=true", "-jar", jar, "-tsvg", "-pipe", "-nometadata",
    stdin_data: src
  )
  if status.success? && !stdout.empty?
    File.write(out, stdout)
    puts "  [jar] #{File.basename(out)}"
    true
  else
    puts "  [WARN] jar: #{stderr.strip[0..100]}"
    false
  end
end

def render_online(src, out)
  compressed = Zlib::Deflate.deflate(src.strip, Zlib::BEST_COMPRESSION)
  encoded = encode64(compressed.bytes)
  uri = URI("https://www.plantuml.com/plantuml/svg/#{encoded}")
  resp = Net::HTTP.get_response(uri)
  if resp.is_a?(Net::HTTPSuccess)
    File.write(out, resp.body)
    puts "  [online] #{File.basename(out)}"
    true
  else
    puts "  [ERROR] online: #{resp.code}"
    false
  end
rescue => e
  puts "  [ERROR] online: #{e.message}"
  false
end

FileUtils.mkdir_p(OUT)

total = 0
rendered = 0
cached = 0

puts "=== PlantUML Pre-render ==="
puts "Jar: #{JAR || "NOT FOUND (will use online fallback)"}"
puts ""

Dir.glob(File.join(POSTS, "**", "*.md")).each do |fp|
  content = File.read(fp, encoding: "UTF-8")
  blocks = []
  content.scan(/```plantuml\s*\n(.*?)```/m) { |m| blocks << m[0].strip }
  next if blocks.empty?

  puts "#{fp.sub(POSTS, "")} (#{blocks.length})"

  blocks.each do |src|
    total += 1
    hash = Digest::SHA256.hexdigest(src.strip)[0..15]
    svg = File.join(OUT, "#{hash}.svg")

    if File.exist?(svg)
      puts "  [cached] #{hash}.svg"
      cached += 1
      next
    end

    ok = JAR ? render_jar(JAR, src, svg) : false
    ok = render_online(src, svg) unless ok
    rendered += 1 if ok
  end
end

puts ""
puts "Done: #{total} blocks, #{rendered} rendered, #{cached} cached"
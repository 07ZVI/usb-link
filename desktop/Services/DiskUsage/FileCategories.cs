namespace Suhang.Desktop.DiskUsage;

internal static class FileCategories
{
    static readonly Dictionary<string,FileCategory> extensions = Create();
    static Dictionary<string,FileCategory> Create() {
        var result=new Dictionary<string,FileCategory>(StringComparer.OrdinalIgnoreCase);
        Add(FileCategory.Video,"mp4 mkv avi mov wmv webm m4v mpg mpeg mts m2ts ts vob flv ogv 3gp 3g2 asf rm rmvb divx f4v");
        Add(FileCategory.Audio,"mp3 flac wav aac m4a ogg opus wma aiff aif alac ape mid midi amr ac3 dts mka au snd");
        Add(FileCategory.Image,"jpg jpeg png gif webp bmp tif tiff heic heif avif svg ico icns raw cr2 cr3 nef arw dng psd ai eps jxl tga exr hdr jp2");
        Add(FileCategory.Document,"pdf doc docx xls xlsx ppt pptx odt ods odp rtf txt md markdown csv tsv epub mobi azw azw3 djvu pages numbers key one tex bib org rst chm");
        Add(FileCategory.Archive,"zip 7z rar tar gz bz2 xz zst tgz tbz tbz2 txz lz lzma cab arj ace sit sitx br");
        Add(FileCategory.Code,"cs go swift c h cpp hpp cc cxx m mm rs py pyw js jsx ts tsx mts cts java kt kts scala rb php sh bash zsh fish ps1 bat cmd sql html htm css scss sass less vue svelte json jsonc yaml yml toml xml xaml axaml ini conf config fs fsx vb lua dart r pl pm ex exs erl hrl clj cljs edn asm s sln csproj vcxproj gradle cmake make ipynb graphql proto lock");
        Add(FileCategory.Application,"exe msi msix appx appxbundle msixbundle com scr app apk aab ipa deb rpm pkg wasm jar class so dylib pdb");
        Add(FileCategory.DiskImage,"iso img dmg vhd vhdx vmdk qcow qcow2 vdi sparseimage sparsebundle bin cue nrg toast wim esd");
        Add(FileCategory.System,"sys dll drv dmp etl log evtx dat reg blf pol db wal shm tmp bak cache");
        return result;
        void Add(FileCategory category,string names) { foreach(var name in names.Split(' '))result["."+name]=category; }
    }
    internal static FileCategory Classify(string extensionWithDot) => extensions.GetValueOrDefault(extensionWithDot,FileCategory.Other);
    internal static string Label(FileCategory category) => category switch {
        FileCategory.Video=>"影片",FileCategory.Audio=>"音訊",FileCategory.Image=>"圖片",FileCategory.Document=>"文件",
        FileCategory.Archive=>"壓縮檔",FileCategory.Code=>"程式碼",FileCategory.Application=>"應用程式",
        FileCategory.DiskImage=>"磁碟映像",FileCategory.System=>"系統",_=>"其他"
    };
}

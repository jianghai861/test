|指令| 含义 |备注|
|:--|:--|:--|
|git --version|查询git版本||
|sudo apt install -y git|重新安装 Git|linux系统|
|ll|仓库目录||
|ls|仓库目录||
|ls -al|仓库目录-含隐藏目录||
| git remote -v                                                | 查看本地仓库所关联的远程仓库信息：                           ||
|git clone -o origin01 https://github.com/jianghai861/test.git test|-o 修改主机名。默认origin 后面test为本地仓库的主目录名||
|git init|把当前所在目录变成一个本地仓库，为自己搭建服务器用（不建议）||
|rm -rf 01.txt|删除该目录下的 01.txt文件||
|git status|查看仓库状态||
|git add 01.txt|添加 01.txt 文件到暂存区||
|git add .|把当前目录修改的文件全部添加到暂存区||
|git reset -- 01.txt|删除暂存区的 01.txt 的修改||
|git reset --|删除所有暂存区的修改||
|git diff --cached|查看暂存区的全部修改||
|git log [分支名]|查看某分支的提交历史，不写分支名查看当前所在分支||
|git log --oneline|一行显示提交历史||
|git log -n|其中 n 是数字，查看最近 n 个提交||
|git log --author [贡献者名字]|查看指定贡献者的提交记录||
|git log --graph|图示法显示提交历史||
|git log --reverse|按时间正序排列查看提交的版本信息||
|git branch -avv|查看全部分支信息||
|git commit -m "hhhhh"|把暂存区的修改提交到版本区生成一个新的版本||
|git config --global user.email "jiang_hai861@qq.com"|对Git进行本地配置，邮箱||
|git config --global user.name "jianghai861"| 对Git进行本地配置，用户名                                    ||
|git config -l|查看配置信息||
|cat -n ~/.gitconfig|查询主目录中隐藏文件 .gitconfig||
|git reset --soft HEAD^|撤销最近的1次提交，将修改还原到暂存区||
|git reset --soft HEAD^^|撤销最近的2次提交||
|git reset --soft HEAD~n|撤销最近的n次提交||
|git remote add origin https://github.com/jianghai861/test.git|本地和远程仓库的连接,后缀  .git不能少||
|git push -u origin master|把本地仓库master分支push到远程仓库里去||
||||
||||
||||
||||
||||
||||
||||
||||
||||
||||
||||
||||
||||
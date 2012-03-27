<?php
namespace apacheLogParser;

class ApacheLogFile{
    /**
     * The file contents of the log file
     * 
     * @var string
     */
    protected $file='';
    /**
     * The parsed out log entries
     * 
     * @var array[int]ApacheLogRecord
     */
    protected $rows=array();
    /**
     * The Apache CustomLog/LogFormat for the log file
     * 
     * @var string
     * @see https://httpd.apache.org/docs/2.0/mod/mod_log_config.html
     */
    protected $format='';
    /**
     * The expected pieces of the log parsed from $format
     * 
     * @var array[int]string
     */
    protected $logPieces = array();
    
               
    /**
     * Creates the ApacheLogFile instance
     * @param string $logFile The log to parse
     * @param string $format The Apache CustomLog/LogFormat for the log file
     * 
     * @return null
     */
    public function __construct($logFile, $format){
        $this->file = $logFile;
        $this->format = $format;
    }
    
    /**
     * Gets a specified ApacheLogRecord or the entire array of them
     * 
     * If this is the first time calling it, the log will be parsed before 
     * returning a record.
     * 
     * @param int $row [Optional] Default = -1 If -1, returns all records in an array
     * 
     * @return array[int]ApacheLogRecord|ApacheLogRecord 
     */
    public function getRow($row=-1){
        if(empty($this->rows)){
            $this->_parseLog();
        }
        if($row==-1){return $this->rows;}
        else{return $this->rows[$row];}
    }
    
    /**
     * Parses the log file using a regular expression generated from $this->format
     * 
     * @return void
     */
    protected function _parseLog(){
        $regEx = $this->_convertFormatToRegEx();
        $matches = array();
        preg_match_all($regEx, $this->file, $matches,PREG_SET_ORDER);
        foreach($matches as $match){
            $logEntry = new ApacheLogRecord();
            foreach($this->logPieces as $key=>$piece){
               $logEntry->logValue($piece,$match[$key+1]);
            }
            $this->rows[]=$logEntry;
        }
    }
    
    /**
     * Parses the Apache log format into a regular expression 
     * 
     * @return string
     */
    protected function _convertFormatToRegEx(){
        $regEx = '/^';
        $segment = '';
        $segmentStartChar='';
        $pcreSpecChars = array('[',']','*','.','(',')','^','$','+','?','|','{','}');
        $endChars = array('%','a','A','b','B','C','D','e','f','h','H','i','l',
            'm','n','o','p','P','q','r','s','t','T','u','U','v','V','X','I','O');
        for($x=0;$x<strlen($this->format);$x++){
            $newChar = $this->format[$x];
            if(!empty($segmentStartChar)){
                //process special character segments
                if($segmentStartChar=='%' && in_array($newChar,$endChars)){
                    $regEx.=$this->_processApacheLogCommand($newChar,$segment);
                    $segment='';
                    $segmentStartChar='';
                }
                else{
                    if($newChar=='{'){$segmentStartChar = '{';}
                    elseif($newChar=='}'){$segmentStartChar = '%';}
                    $segment.= $newChar;
                }
            }
            elseif($newChar=='%'){
                //the new character is starting a special set for an Apache log command
                $segmentStartChar = $newChar;
            }
            else{
                if(in_array($newChar,$pcreSpecChars)){$regEx.= '\\'.$newChar;}
                else{$regEx.= $newChar;}
            }
        }
        return $regEx.'$/Umi';
    }
    
    /**
     * Turns a specific Apache log directive element into a regular expression
     * 
     * @param string $command
     * @param string $segment
     * 
     * @return string
     * @todo This is not complete, there are a number of directives that
     *       should be made more accurate or that haven't been created yet
     * @todo This doesn't handle < or > modifiers except for the %...s directive
     */
    protected function _processApacheLogCommand($command,$segment){
        switch($command){
            case '%':
                return '%';
                break;
            case 'a':
                $this->logPieces[]='remoteIP';
                return '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})';
                break;
            case 'A':
                $this->logPieces[]='localIP';
                return '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})';
                break;
            case 'b':
                $this->logPieces[]='respBytes';
                return '(\S+)';
                break;
            case 'B':
                $this->logPieces[]='respBytes';
                return '(\d*)';
                break;
            case 'C':
                $cookie = preg_replace('/.*{(.*)}/', '$1', $segment);
                $this->logPieces[]='cookie:'.$cookie;
                return '(.*)';
                break;
            case 'D':
                $this->logPieces[]='respMicro';
                return '(\d*)';
                break;
            case 'e':
                $env = preg_replace('/.*{(.*)}/U', '$1', $segment);
                $this->logPieces[]='environment:'.$env;
                return '(.*)';
                break;
            case 'f':
                $this->logPieces[]='filename';
                return '(.*)';
                break;
            case 'h':
                $this->logPieces[]='clientIP';
                return '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})';
                //TODO: Set this up to handle host names as well as IPs
                break;
            case 'H':
                $this->logPieces[]='protocol';
                //TODO: Don't know what regular expression to put here
                break;
            case 'i':
                $header = preg_replace('/.*{(.*)}/U', '$1', $segment);
                $this->logPieces[]='reqHeader:'.$header;
                return '(.*)';
                break;
            case 'l':
                $this->logPieces[]='remoteLogname';
                //TODO: Don't know what regular expression to put here
                //using just a - right now
                return '(-)';
                break;
            case 'm':
                $this->logPieces[]='reqMethod';
                return '(GET|POST|PUT|HEAD|OPTIONS|DELETE|TRACE|CONNECT)';
                break;
            case 'n':
                $module = preg_replace('/.*{(.*)}/U', '$1', $segment);
                $this->logPieces[]='module:'.$module;
                return '(.*)';
                break;
            case 'o':
                $header = preg_replace('/.*{(.*)}/U', '$1', $segment);
                $this->logPieces[]='respHeader:'.$header;
                return '(.*)';
                break;
            case 'p':
                $this->logPieces[]='port';
                return '(\d*)';
                break;
            case 'P':
                if(preg_match('/.*{(.*)}/U', $segment)>0){
                    $this->logPieces[]=preg_replace('/.*{(.*)}/U', '$1', $segment);
                }
                else{$this->logPieces[]='pid';}
                return '(\d*)';
                break;
            case 'q':
                $this->logPieces[]='queryString';
                return '(\S*)';
                break;
            case 'r':
                $this->logPieces[]='request';
                return '(.*)';
                break;
            case 's':
                if(preg_match('/>$/',$segment)>0){$this->logPieces[]='lastStatus';}
                else{$this->logPieces[]='firstStatus';}
                return '(\d{3})';
                break;
            case 't':
                //TODO: Set up to handle alternative formats
                $this->logPieces[]='reqTime';
                return '\[(.*)\]';
                break;
            case 'T':
                $this->logPieces[]='respSec';
                return '(\d*)';
                break;
            case 'u':
                $this->logPieces[]='user';
                return '(.*)';
                break;
            case 'U':
                $this->logPieces[]='url';
                return '(.*)';
                break;
            case 'v':
                $this->logPieces[]='serverName';
                return '(.*)';
                break;
            case 'V':
                $this->logPieces[]='useCanonicalServerName';
                return '(.*)';
                break;
            case 'X':
                $this->logPieces[]='completeConnStatus';
                return '(X|\+|-)';
                break;
            case 'I':
                $this->logPieces[]='libIOBytesIn';
                return '(\d*)';
                break;
            case 'O':
                $this->logPieces[]='libIOBytesOut';
                return '(\d*)';
                break;
        }
    }
}
?>

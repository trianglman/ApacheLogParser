<?php
namespace apacheLogParser;
class FunctionalTest  extends \PHPUnit_Framework_TestCase{
    
    /**
     * Log formats to be used for testing
     * @var array[string]string
     */
    protected $logFormats=array();
    /**
     * Paths to the log files to be used for testing
     * @var array[string]string
     */
    protected $logFiles = array();
    
    protected function setUp() {
        //Common Apache log formats
        $this->logFormats['common']="%h %l %u %t \\\"%r\\\" %>s %b";
        $this->logFormats['combined']="%h %l %u %t \\\"%r\\\" %>s %b "
                ."\\\"%{Referer}i\\\" \\\"%{User-Agent}i\\\"";
        //tests that all basic parameters gets translated properly
        $this->logFormats['allStandard']="%% %a %A %b %B %D \\\"%f\\\" %h %l "
                ."%m %p %q \\\"%r\\\" %s %t %T \\\"%u\\\" \\\"%U\\\" \\\"%v\\\" "
                ."\\\"%V\\\" %X %I %O";
        //Tests that all formats that accept a segment are captured
        $this->logFormats['allSegmented']="\\\"%{foo}C\\\" \\\"%{foo}e\\\" "
                ."\\\"%{Referer}i\\\" \\\"%{foo}n\\\" \\\"%{Server}o\\\" "
                ."\\\"%{tid}P\\\" \\\"%{pid}P\\\" \\\"%>s\\\"";
        //tests that logging conditions are ignored
        $this->logFormats['conditional']="\\\"%!200,304,302{Referer}i\\\"";
        //log files to match each of the log formats
        $this->logFiles['common']=dirname(__FILE__).'/testAssets/commonlog';
        $this->logFiles['combined']=dirname(__FILE__).'/testAssets/combinedlog';
        $this->logFiles['allStandard']=dirname(__FILE__).'/testAssets/allStandardlog';
        $this->logFiles['allSegmented']=dirname(__FILE__).'/testAssets/allSegmentedlog';
        $this->logFiles['conditional']=dirname(__FILE__).'/testAssets/conditionallog';
        
    }

    public function teardown()
    {
    }
    
    public function testParseCommonFile(){
        $log = new ApacheLogFile(file_get_contents($this->logFiles['common']),
                $this->logFormats['common']);
        
        $this->assertEquals(14,count($log->getRow()));
        $this->assertEquals('127.0.0.1',$log->getRow(2)->getClientIP());
        $this->assertEquals('-',$log->getRow(2)->getRemoteLogname());
        $this->assertEquals('-',$log->getRow(2)->getUser());
        $this->assertEquals('24/Mar/2012:22:36:29',
                $log->getRow(2)->getReqTime()->format('d/M/Y:H:i:s'));
        $this->assertEquals('GET /activity/scripts/jquery-1.6.4.js HTTP/1.1',
                $log->getRow(2)->getRequest());
        $this->assertEquals(200,$log->getRow(2)->getLastStatus());
        $this->assertEquals(238159,$log->getRow(2)->getRespBytes());
    }
    
    public function testParseCombinedFile(){
        $log = new ApacheLogFile(file_get_contents($this->logFiles['combined']),
                $this->logFormats['combined']);
        
        $this->assertEquals(10,count($log->getRow()));
        $this->assertEquals('127.0.0.1',$log->getRow(4)->getClientIP());
        $this->assertEquals('-',$log->getRow(4)->getRemoteLogname());
        $this->assertEquals('-',$log->getRow(4)->getUser());
        $this->assertEquals('24/Mar/2012:21:55:19',
                $log->getRow(4)->getReqTime()->format('d/M/Y:H:i:s'));
        $this->assertEquals('GET /activity/scripts/jquery-1.6.4.js HTTP/1.1',
                $log->getRow(4)->getRequest());
        $this->assertEquals(200,$log->getRow(4)->getLastStatus());
        $this->assertEquals(238159,$log->getRow(4)->getRespBytes());
        $this->assertEquals('http://www.example.com/activity/',
                $log->getRow(4)->getReqHeader('Referer'));
        $this->assertEquals('Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:11.0) '
                .'Gecko/20100101 Firefox/11.0',
                $log->getRow(4)->getReqHeader('User-Agent'));
    }

    public function testParseAllStandardFile(){
        $log = new ApacheLogFile(file_get_contents($this->logFiles['allStandard']),
                $this->logFormats['allStandard']);
        
        $this->assertEquals(7,count($log->getRow()));
        $this->assertEquals('127.0.0.1',$log->getRow(3)->getRemoteIP());
        $this->assertEquals('192.168.0.104',$log->getRow(3)->getLocalIP());
        $this->assertEquals(418,$log->getRow(3)->getRespBytes());
        $this->assertEquals(12371,$log->getRow(3)->getRespMicro());
        $this->assertEquals('/var/www/activity/scripts/global.js',
                $log->getRow(3)->getFilename());
        $this->assertEquals('127.0.0.1',$log->getRow(3)->getClientIP());
        $this->assertEquals('-',$log->getRow(3)->getRemoteLogname());
        $this->assertEquals('GET',$log->getRow(3)->getReqMethod());
        $this->assertEquals(80,$log->getRow(3)->getPort());
        $this->assertEquals('',$log->getRow(3)->getQueryString());
        $this->assertEquals('GET /activity/scripts/global.js HTTP/1.1',
                $log->getRow(3)->getRequest());
        $this->assertEquals(200,$log->getRow(3)->getFirstStatus());
        $this->assertEquals('24/Mar/2012:22:05:48',
                $log->getRow(3)->getReqTime()->format('d/M/Y:H:i:s'));
        $this->assertEquals(0,$log->getRow(3)->getRespSec());
        $this->assertEquals('-',$log->getRow(3)->getUser());
        $this->assertEquals('/activity/scripts/global.js',
                $log->getRow(3)->getUrl());
        $this->assertEquals('www.example.com',$log->getRow(3)->getServerName());
        $this->assertEquals('www.example.com',
                $log->getRow(3)->getUseCanonicalServerName());
        $this->assertEquals('keep-alive',$log->getRow(3)->getCompleteConnStatus());
        $this->assertEquals(100,$log->getRow(3)->getLibIOBytesIn());
        $this->assertEquals(3540,$log->getRow(3)->getLibIOBytesOut());
    }
    
    public function testParseAllSegmentedFile(){
        $log = new ApacheLogFile(file_get_contents($this->logFiles['allSegmented']),
                $this->logFormats['allSegmented']);
        
        $this->assertEquals(4,count($log->getRow()));
        $this->assertEquals('bar',$log->getRow(0)->getCookie('foo'));
        $this->assertEquals('baz',$log->getRow(0)->getEnvironment('foo'));
        $this->assertEquals('http://www.example.com/activity/page2.php?variable=7',
                $log->getRow(0)->getReqHeader('Referer'));
        $this->assertEquals('bar', $log->getRow(0)->getModule('foo'));
        $this->assertEquals('Apache/2.4.1 (Unix) OpenSSL/1.0.0g',
                $log->getRow(0)->getRespHeader('Server'));
        $this->assertEquals('3052276592',$log->getRow(0)->getTid());
        $this->assertEquals('27654',$log->getRow(0)->getPid());
        $this->assertEquals(200,$log->getRow(0)->getLastStatus());
    }
    
    public function testParseConditionalFile(){
        $log = new ApacheLogFile(file_get_contents($this->logFiles['conditional']),
                $this->logFormats['conditional']);
        
        $this->assertEquals(11,count($log->getRow()));
        $this->assertEquals('http://trianglman.dyndns-ip.com/videoViewer/index.php',
                $log->getRow(4)->getReqHeader('Referer'));
        foreach($log->getRow() as $index=>$row){
            if($index!==4){
                $this->assertEquals('-',$row->getReqHeader('Referer'));
            }
        }
    }
    
}

?>
